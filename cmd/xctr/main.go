package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/flomesh-io/xnet/pkg/k8s"
	"github.com/flomesh-io/xnet/pkg/k8s/informers"
	"github.com/flomesh-io/xnet/pkg/logger"
	"github.com/flomesh-io/xnet/pkg/messaging"
	"github.com/flomesh-io/xnet/pkg/signals"
	"github.com/flomesh-io/xnet/pkg/version"
	"github.com/flomesh-io/xnet/pkg/xnet/cni/controller"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

var (
	verbosity    string
	meshName     string // An ID that uniquely identifies an FSM instance
	fsmVersion   string
	fsmNamespace string

	filterPortInbound  string
	filterPortOutbound string

	flushTCPConnTrackCrontab     string
	flushTCPConnTrackIdleSeconds int
	flushTCPConnTrackBatchSize   int

	flushUDPConnTrackCrontab     string
	flushUDPConnTrackIdleSeconds int
	flushUDPConnTrackBatchSize   int

	nodePathCniBin  string
	nodePathCniNetd string
	nodePathSysFs   string
	nodePathSysRun  string

	rtScheme = runtime.NewScheme()

	flags = pflag.NewFlagSet(`fsm-xnet`, pflag.ExitOnError)
	log   = logger.New("fsm-xnet-switcher")
)

func init() {
	flags.StringVarP(&verbosity, "verbosity", "v", "info", "Set log verbosity level")
	flags.StringVar(&meshName, "mesh-name", "", "FSM mesh name")
	flags.StringVar(&fsmVersion, "fsm-version", "", "Version of FSM")
	flags.StringVar(&fsmNamespace, "fsm-namespace", "", "FSM controller's namespace")

	flags.StringVar(&filterPortInbound, "filter-port-inbound", "inbound", "filter inbound port flag")
	flags.StringVar(&filterPortOutbound, "filter-port-outbound", "outbound", "filter outbound port flag")

	flags.StringVar(&flushTCPConnTrackCrontab, "flush-tcp-conn-track-cron-tab", "30 3 */1 * *", "flush tcp conn track cron tab")
	flags.IntVar(&flushTCPConnTrackIdleSeconds, "flush-tcp-conn-track-idle-seconds", 3600, "flush tcp flow idle seconds")
	flags.IntVar(&flushTCPConnTrackBatchSize, "flush-tcp-conn-track-batch-size", 4096, "flush tcp flow batch size")

	flags.StringVar(&flushUDPConnTrackCrontab, "flush-udp-conn-track-cron-tab", "*/2 * * * *", "flush udp conn track cron tab")
	flags.IntVar(&flushUDPConnTrackIdleSeconds, "flush-udp-conn-track-idle-seconds", 120, "flush udp conn track idle seconds")
	flags.IntVar(&flushUDPConnTrackBatchSize, "flush-udp-conn-track-batch-size", 4096, "flush udp conn track batch size")

	flags.StringVar(&nodePathCniBin, "node-path-cni-bin", "", "cni bin node path")
	flags.StringVar(&nodePathCniNetd, "node-path-cni-netd", "", "cni net-d node path")
	flags.StringVar(&nodePathSysFs, "node-path-sys-fs", "", "sys fs node path")
	flags.StringVar(&nodePathSysRun, "node-path-sys-run", "", "sys run node path")

	_ = scheme.AddToScheme(rtScheme)
}

func parseFlags() error {
	if err := flags.Parse(os.Args); err != nil {
		return err
	}
	_ = flag.CommandLine.Parse([]string{})

	if len(nodePathCniBin) > 0 {
		volume.CniBin.HostPath = nodePathCniBin
	}
	if len(nodePathCniNetd) > 0 {
		volume.CniNetd.HostPath = nodePathCniNetd
	}
	if len(nodePathSysFs) > 0 {
		volume.Sysfs.HostPath = nodePathSysFs
	}
	if len(nodePathSysRun) > 0 {
		volume.SysRun.HostPath = nodePathSysRun
		volume.Netns.HostPath = path.Join(volume.SysRun.HostPath, `netns`)
	}

	return nil
}

// validateCLIParams contains all checks necessary that various permutations of the CLI flags are consistent
func validateCLIParams() error {
	if meshName == "" {
		return fmt.Errorf("please specify the mesh name using --mesh-name")
	}

	if fsmNamespace == "" {
		return fmt.Errorf("please specify the FSM namespace using --fsm-namespace")
	}

	return nil
}

func main() {
	log.Info().Msgf("Starting fsm-xnet-switcher %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
	if err := parseFlags(); err != nil {
		log.Fatal().Err(err).Msg("Error parsing cmd line arguments")
	}
	if err := logger.SetLogLevel(verbosity); err != nil {
		log.Fatal().Err(err).Msg("Error setting log level")
	}

	// This ensures CLI parameters (and dependent values) are correct.
	if err := validateCLIParams(); err != nil {
		log.Fatal().Err(err).Msg("Error validating CLI parameters")
	}

	// Initialize kube config and client
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating kube configs using in-cluster config")
	}
	kubeClient := kubernetes.NewForConfigOrDie(kubeConfig)

	opts := []informers.InformerCollectionOption{
		informers.WithKubeClient(kubeClient),
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := signals.RegisterExitHandlers(cancel)

	msgBroker := messaging.NewBroker(stop)

	informerCollection, err := informers.NewInformerCollection(meshName, fsmNamespace, stop, opts...)
	if err != nil {
		log.Fatal().Err(err).Msg("Error creating informer collection")
	}

	kubeController := k8s.NewKubernetesController(informerCollection, msgBroker)

	server := controller.NewServer(ctx, kubeController, msgBroker, stop,
		filterPortInbound, filterPortOutbound,
		flushTCPConnTrackCrontab, flushTCPConnTrackIdleSeconds, flushTCPConnTrackBatchSize,
		flushUDPConnTrackCrontab, flushUDPConnTrackIdleSeconds, flushUDPConnTrackBatchSize)
	if err = server.Start(); err != nil {
		log.Fatal().Err(err)
	}

	<-stop

	log.Info().Msgf("Stopping fsm-xnet-switcher %s; %s; %s", version.Version, version.GitCommit, version.BuildDate)
}
