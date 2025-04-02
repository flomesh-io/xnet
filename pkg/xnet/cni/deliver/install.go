package deliver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/pkg/errors"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf"
	"github.com/flomesh-io/xnet/pkg/xnet/cni"
	"github.com/flomesh-io/xnet/pkg/xnet/util"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

type Installer struct {
	workDir string

	cniConfigFilepath string
}

// NewInstaller returns an instance of Installer with the given config
func NewInstaller(workDir string) *Installer {
	return &Installer{workDir: workDir}
}

// Run starts the installation process, verifies the configuration, then sleeps.
// If an invalid configuration is detected, the installation process will restart to restore a valid state.
func (in *Installer) Run(ctx context.Context, cniReady chan struct{}) error {
	for {
		err := in.copyBinaries()
		if err != nil {
			return err
		}

		if in.cniConfigFilepath, err = in.createCNIConfigFile(ctx); err != nil {
			return err
		}
		if len(cniReady) == 0 {
			cniReady <- struct{}{}
		}

		if err = in.sleepCheckInstall(ctx, in.cniConfigFilepath); err != nil {
			return err
		}
		log.Debug().Msg("restarting cni installer...")
	}
}

// Cleanup remove CNI's config, kubeconfig file, and binaries.
func (in *Installer) Cleanup(ctx context.Context) error {
	log.Debug().Msg("Cleaning up.")
	if len(in.cniConfigFilepath) == 0 {
		cniConfigFilepath, err := in.getCNIConfigFilepath(ctx)
		if err != nil {
			return err
		}
		in.cniConfigFilepath = cniConfigFilepath
	}

	if len(in.cniConfigFilepath) > 0 && util.Exists(in.cniConfigFilepath) {
		log.Debug().Msgf("removing cni config from cni config file: %s", in.cniConfigFilepath)

		// Read JSON from CNI config file
		cniConfigMap, err := in.readCNIConfigMap(in.cniConfigFilepath)
		if err != nil {
			return err
		}
		// Find CNI and remove from plugin list
		plugins, err := util.GetPlugins(cniConfigMap)
		if err != nil {
			return errors.Wrap(err, in.cniConfigFilepath)
		}
		for i, rawPlugin := range plugins {
			plugin, err := util.GetPlugin(rawPlugin)
			if err != nil {
				return errors.Wrap(err, in.cniConfigFilepath)
			}
			if plugin["type"] == cni.PluginName {
				cniConfigMap["plugins"] = append(plugins[:i], plugins[i+1:]...)
				break
			}
		}

		cniConfig, err := util.MarshalCNIConfig(cniConfigMap)
		if err != nil {
			return err
		}
		if err = util.AtomicWrite(in.cniConfigFilepath, cniConfig, os.FileMode(0o644)); err != nil {
			return err
		}
	}

	log.Debug().Msg("removing existing binaries")
	cniBinPath := path.Join(volume.CniBin.MountPath, cni.PluginName)
	if util.Exists(cniBinPath) {
		if err := os.Remove(cniBinPath); err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) copyBinaries() error {
	loopbackCli := path.Join(volume.CniBin.MountPath, cni.PluginLoopBack)
	if exists := util.Exists(loopbackCli); !exists {
		if _, err := os.Lstat(loopbackCli); err != nil {
			return fmt.Errorf("%s is not cni bin directory for missing loopback cli", volume.CniBin.MountPath)
		}
	}

	dstFile := path.Join(volume.CniBin.MountPath, cni.PluginName)
	if exists := util.Exists(dstFile); exists {
		return nil
	}

	if util.IsDirWriteable(volume.CniBin.MountPath) != nil {
		return fmt.Errorf("directory %s is not writable", volume.CniBin.MountPath)
	}

	srcFile := path.Join(in.workDir, fmt.Sprintf(`.%s/.%s`, bpf.FSM_PROG_NAME, cni.PluginName))
	if err := util.AtomicCopy(srcFile, volume.CniBin.MountPath, cni.PluginName); err != nil {
		return err
	}
	log.Debug().Msgf("copied %s to %s", srcFile, dstFile)

	return nil
}

func (in *Installer) createCNIConfigFile(ctx context.Context) (string, error) {
	cniConfig := fmt.Sprintf(`{"type": "%s"}`, cni.PluginName)
	return in.writeCNIConfig(ctx, []byte(cniConfig))
}

func (in *Installer) writeCNIConfig(ctx context.Context, cniConfig []byte) (string, error) {
	cniConfigFilepath, err := in.getCNIConfigFilepath(ctx)
	if err != nil {
		return "", err
	}

	// This section overwrites an existing plugins list entry for fsm-cni
	//#nosec G304
	existingCNIConfig, err := os.ReadFile(cniConfigFilepath)
	if err != nil {
		return "", err
	}
	mergeConfig, err := in.insertCNIConfig(cniConfig, existingCNIConfig)
	if err != nil {
		return "", err
	}

	if err = util.AtomicWrite(cniConfigFilepath, mergeConfig, os.FileMode(0o644)); err != nil {
		return "", err
	}

	if strings.HasSuffix(cniConfigFilepath, ".conf") {
		// If the old CNI config filename ends with .conf, rename it to .conflist, because it has to be changed to a list
		log.Debug().Msgf("renaming %s extension to .conflist", cniConfigFilepath)
		err = os.Rename(cniConfigFilepath, cniConfigFilepath+pluginListSuffix)
		if err != nil {
			return "", err
		}
		cniConfigFilepath += pluginListSuffix
	}

	return cniConfigFilepath, nil
}

// If configured as chained CNI plugin, waits indefinitely for a main CNI config file to exist before returning
// Or until cancelled by parent context
func (in *Installer) getCNIConfigFilepath(ctx context.Context) (string, error) {
	watcher, fileModified, errChan, err := util.CreateFileWatcher(volume.CniNetd.MountPath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = watcher.Close()
	}()

	filename, err := in.getDefaultCNINetwork(volume.CniNetd.MountPath)
	for len(filename) == 0 {
		filename, err = in.getDefaultCNINetwork(volume.CniNetd.MountPath)
		if err == nil {
			break
		}
		if err = util.WaitForFileMod(ctx, fileModified, errChan); err != nil {
			return "", err
		}
	}

	cniConfigFilepath := filepath.Join(volume.CniNetd.MountPath, filename)

	for !util.Exists(cniConfigFilepath) {
		if strings.HasSuffix(cniConfigFilepath, ".conf") && util.Exists(cniConfigFilepath+pluginListSuffix) {
			log.Debug().Msgf("%s doesn't exist, but %[1]slist does; Using it as the CNI config file instead.", cniConfigFilepath)
			cniConfigFilepath += pluginListSuffix
		} else if strings.HasSuffix(cniConfigFilepath, ".conflist") && util.Exists(cniConfigFilepath[:len(cniConfigFilepath)-4]) {
			log.Debug().Msgf("%s doesn't exist, but %s does; Using it as the CNI config file instead.", cniConfigFilepath, cniConfigFilepath[:len(cniConfigFilepath)-4])
			cniConfigFilepath = cniConfigFilepath[:len(cniConfigFilepath)-4]
		} else {
			log.Debug().Msgf("CNI config file %s does not exist. Waiting for file to be written...", cniConfigFilepath)
			if err = util.WaitForFileMod(ctx, fileModified, errChan); err != nil {
				return "", err
			}
		}
	}

	return cniConfigFilepath, err
}

func (in *Installer) insertCNIConfig(cniConfig, existingCNIConfig []byte) ([]byte, error) {
	var pluginMap map[string]interface{}
	if err := json.Unmarshal(cniConfig, &pluginMap); err != nil {
		return nil, fmt.Errorf("error loading CNI config (JSON error): %v", err)
	}

	var existingMap map[string]interface{}
	if err := json.Unmarshal(existingCNIConfig, &existingMap); err != nil {
		return nil, fmt.Errorf("error loading existing CNI config (JSON error): %v", err)
	}

	var newMap map[string]interface{}

	if _, ok := existingMap["type"]; ok {
		// Assume it is a regular network conf file
		delete(existingMap, "cniVersion")

		plugins := make([]map[string]interface{}, 2)
		plugins[0] = existingMap
		plugins[1] = pluginMap

		newMap = map[string]interface{}{
			"name":       "k8s-pod-network",
			"cniVersion": "0.3.1",
			"plugins":    plugins,
		}
	} else {
		// Assume it is a network list file
		newMap = existingMap
		plugins, err := util.GetPlugins(newMap)
		if err != nil {
			return nil, fmt.Errorf("existing CNI config: %v", err)
		}

		for _, rawPlugin := range plugins {
			plugin, err := util.GetPlugin(rawPlugin)
			if err != nil {
				return nil, fmt.Errorf("existing CNI plugin: %v", err)
			}
			if plugin["type"] == cni.PluginName {
				// it already contains fsm-cni
				return util.MarshalCNIConfig(newMap)
			}
		}

		newMap["plugins"] = append(plugins, pluginMap)
	}

	return util.MarshalCNIConfig(newMap)
}

// Follows the same semantics as kubelet
// https://github.com/kubernetes/kubernetes/blob/954996e231074dc7429f7be1256a579bedd8344c/pkg/kubelet/dockershim/network/cni/cni.go#L144-L184
func (in *Installer) getDefaultCNINetwork(confDir string) (string, error) {
	files, err := libcni.ConfFiles(confDir, []string{".conf", ".conflist"})
	switch {
	case err != nil:
		return "", err
	case len(files) == 0:
		return "", fmt.Errorf("no networks found in %s", confDir)
	}

	sort.Strings(files)
	for _, confFile := range files {
		var confList *libcni.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				log.Warn().Msgf("Error loading CNI config list file %s: %v", confFile, err)
				continue
			}
		} else {
			conf, err := libcni.ConfFromFile(confFile)
			if err != nil {
				log.Warn().Msgf("Error loading CNI config file %s: %v", confFile, err)
				continue
			}
			// Ensure the config has a "type" so we know what plugin to run.
			// Also catches the case where somebody put a conflist into a conf file.
			if conf.Network.Type == "" {
				log.Warn().Msgf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", confFile)
				continue
			}

			confList, err = libcni.ConfListFromConf(conf)
			if err != nil {
				log.Warn().Msgf("Error converting CNI config file %s to list: %v", confFile, err)
				continue
			}
		}
		if len(confList.Plugins) == 0 {
			log.Warn().Msgf("CNI config list %s has no networks, skipping", confList.Name)
			continue
		}

		return filepath.Base(confFile), nil
	}

	return "", fmt.Errorf("no valid networks found in %s", confDir)
}

// Read CNI config from file and return the unmarshalled JSON as a map
func (in *Installer) readCNIConfigMap(path string) (map[string]interface{}, error) {
	//#nosec G304
	cniConfig, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cniConfigMap map[string]interface{}
	if err = json.Unmarshal(cniConfig, &cniConfigMap); err != nil {
		return nil, errors.Wrap(err, path)
	}

	return cniConfigMap, nil
}

// sleepCheckInstall verifies the configuration then blocks until an invalid configuration is detected, and return nil.
// If an error occurs or context is canceled, the function will return the error.
// Returning from this function will set the pod to "NotReady".
func (in *Installer) sleepCheckInstall(ctx context.Context, cniConfigFilepath string) error {
	// Create file watcher before checking for installation
	// so that no file modifications are missed while and after checking
	watcher, fileModified, errChan, err := util.CreateFileWatcher(volume.CniNetd.MountPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = watcher.Close()
	}()

	for {
		if checkErr := in.checkInstall(cniConfigFilepath); checkErr != nil {
			// Pod set to "NotReady" due to invalid configuration
			log.Error().Msgf("Invalid configuration. %v", checkErr)
			return nil
		}
		// Check if file has been modified or if an error has occurred during checkInstall before setting isReady to true
		select {
		case <-fileModified:
			return nil
		case err = <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Valid configuration; set isReady to true and wait for modifications before checking again
			if err = util.WaitForFileMod(ctx, fileModified, errChan); err != nil {
				// Pod set to "NotReady" before termination
				return err
			}
		}
	}
}

// checkInstall returns an error if an invalid CNI configuration is detected
func (in *Installer) checkInstall(cniConfigFilepath string) error {
	defaultCNIConfigFilename, err := in.getDefaultCNINetwork(volume.CniNetd.MountPath)
	if err != nil {
		return err
	}
	defaultCNIConfigFilepath := filepath.Join(volume.CniNetd.MountPath, defaultCNIConfigFilename)
	if defaultCNIConfigFilepath != cniConfigFilepath {
		return fmt.Errorf("cni config file %s preempted by %s", cniConfigFilepath, defaultCNIConfigFilepath)
	}

	if !util.Exists(cniConfigFilepath) {
		return fmt.Errorf("cni config file removed: %s", cniConfigFilepath)
	}

	// Verify that CNI config exists in the CNI config plugin list
	cniConfigMap, err := in.readCNIConfigMap(cniConfigFilepath)
	if err != nil {
		return err
	}
	plugins, err := util.GetPlugins(cniConfigMap)
	if err != nil {
		return errors.Wrap(err, cniConfigFilepath)
	}
	for _, rawPlugin := range plugins {
		plugin, err := util.GetPlugin(rawPlugin)
		if err != nil {
			return errors.Wrap(err, cniConfigFilepath)
		}
		if plugin["type"] == cni.PluginName {
			return nil
		}
	}

	return fmt.Errorf("CNI config removed from CNI config file: %s", cniConfigFilepath)
}
