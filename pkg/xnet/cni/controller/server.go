package controller

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/flomesh-io/xnet/pkg/k8s"
	"github.com/flomesh-io/xnet/pkg/messaging"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/load"
	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
	"github.com/flomesh-io/xnet/pkg/xnet/cni"
	"github.com/flomesh-io/xnet/pkg/xnet/cni/deliver"
	"github.com/flomesh-io/xnet/pkg/xnet/e4lb"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

type server struct {
	ctx            context.Context
	kubeController k8s.Controller
	msgBroker      *messaging.Broker
	stop           chan struct{}

	enableE4lb     bool
	enableE4lbIPv4 bool
	enableE4lbIPv6 bool

	enableMesh bool

	unixSockPath string
	cniReady     chan struct{}

	filterPortInbound  string
	filterPortOutbound string

	flushTCPConnTrackCrontab     string
	flushTCPConnTrackIdleSeconds int
	flushTCPConnTrackBatchSize   int

	flushUDPConnTrackCrontab     string
	flushUDPConnTrackIdleSeconds int
	flushUDPConnTrackBatchSize   int
}

// NewServer returns a new CNI Server.
// the path this the unix path to listen.
func NewServer(ctx context.Context,
	kubeController k8s.Controller, msgBroker *messaging.Broker, stop chan struct{},
	enableE4lb, enableE4lbIPv4, enableE4lbIPv6, enableMesh bool,
	filterPortInbound, filterPortOutbound string,
	flushTCPConnTrackCrontab string, flushTCPConnTrackIdleSeconds, flushTCPConnTrackBatchSize int,
	flushUDPConnTrackCrontab string, flushUDPConnTrackIdleSeconds, flushUDPConnTrackBatchSize int) Server {
	return &server{
		unixSockPath:   cni.GetCniSock(volume.SysRun.MountPath),
		kubeController: kubeController,
		msgBroker:      msgBroker,
		cniReady:       make(chan struct{}, 1),
		ctx:            ctx,
		stop:           stop,

		enableE4lb:     enableE4lb,
		enableE4lbIPv4: enableE4lbIPv4,
		enableE4lbIPv6: enableE4lbIPv6,

		enableMesh: enableMesh,

		filterPortInbound:  filterPortInbound,
		filterPortOutbound: filterPortOutbound,

		flushTCPConnTrackCrontab:     flushTCPConnTrackCrontab,
		flushTCPConnTrackIdleSeconds: flushTCPConnTrackIdleSeconds,
		flushTCPConnTrackBatchSize:   flushTCPConnTrackBatchSize,

		flushUDPConnTrackCrontab:     flushUDPConnTrackCrontab,
		flushUDPConnTrackIdleSeconds: flushUDPConnTrackIdleSeconds,
		flushUDPConnTrackBatchSize:   flushUDPConnTrackBatchSize,
	}
}

func (s *server) Start() error {
	load.ProgLoadAll()

	if !s.enableE4lb {
		e4lb.E4lbOff()
	} else {
		load.InitE4lbConfig(s.enableE4lbIPv4, s.enableE4lbIPv6)
		e4lb.E4lbOn()
	}

	if !s.enableMesh {
		s.uninstallCNI()
		go s.CheckAndResetPods()
	} else {
		load.InitMeshConfig()

		if err := os.RemoveAll(s.unixSockPath); err != nil {
			log.Fatal().Msg(err.Error())
		}
		listen, err := net.Listen("unix", s.unixSockPath)
		if err != nil {
			log.Fatal().Msgf("listen error:%v", err)
		}

		r := mux.NewRouter()
		r.Path(cni.CreatePodURI).
			Methods("POST").
			HandlerFunc(s.PodCreated)

		r.Path(cni.DeletePodURI).
			Methods("POST").
			HandlerFunc(s.PodDeleted)

		ss := http.Server{
			Handler:           r,
			WriteTimeout:      10 * time.Second,
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			go ss.Serve(listen) // nolint: errcheck
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
			select {
			case <-ch:
				s.Stop()
			case <-s.stop:
				s.Stop()
			}
			_ = ss.Shutdown(s.ctx)
		}()

		s.installCNI()

		// wait for cni to be ready
		<-s.cniReady

		go s.broadcastListener()

		go s.CheckAndRepairPods()

		if len(s.flushTCPConnTrackCrontab) > 0 && s.flushTCPConnTrackIdleSeconds > 0 && s.flushTCPConnTrackBatchSize > 0 {
			go s.idleTCPConnTrackFlush(maps.SysMesh)
		}

		if len(s.flushUDPConnTrackCrontab) > 0 && s.flushUDPConnTrackIdleSeconds > 0 && s.flushUDPConnTrackBatchSize > 0 {
			go s.idleUDPConnTrackFlush(maps.SysMesh)
		}
	}

	return nil
}

func (s *server) installCNI() {
	install := deliver.NewInstaller(`/app`)
	go func() {
		if err := install.Run(context.TODO(), s.cniReady); err != nil {
			close(s.cniReady)
			log.Fatal().Msg(err.Error())
		}
		if err := install.Cleanup(context.TODO()); err != nil {
			log.Error().Msgf("Failed to clean up CNI: %v", err)
		}
	}()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
		<-ch
		if err := install.Cleanup(context.TODO()); err != nil {
			log.Error().Msgf("Failed to clean up CNI: %v", err)
		}
	}()
}

func (s *server) uninstallCNI() {
	install := deliver.NewInstaller(`/app`)
	if err := install.Cleanup(context.TODO()); err != nil {
		log.Error().Msgf("Failed to clean up CNI: %v", err)
	}
}

func (s *server) Stop() {
	log.Info().Msg("cni-server stop ...")
	close(s.stop)
}
