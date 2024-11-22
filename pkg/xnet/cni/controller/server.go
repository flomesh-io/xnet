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
	"github.com/flomesh-io/xnet/pkg/xnet/cni"
	"github.com/flomesh-io/xnet/pkg/xnet/cni/deliver"
	"github.com/flomesh-io/xnet/pkg/xnet/volume"
)

type server struct {
	ctx            context.Context
	unixSockPath   string
	kubeController k8s.Controller
	msgBroker      *messaging.Broker
	cniReady       chan struct{}
	stop           chan struct{}

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
func NewServer(ctx context.Context, kubeController k8s.Controller, msgBroker *messaging.Broker, stop chan struct{},
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
	load.InitMeshConfig()

	if err := os.RemoveAll(s.unixSockPath); err != nil {
		log.Fatal().Err(err)
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
		go s.idleTCPConnTrackFlush()
	}

	if len(s.flushUDPConnTrackCrontab) > 0 && s.flushUDPConnTrackIdleSeconds > 0 && s.flushUDPConnTrackBatchSize > 0 {
		go s.idleUDPConnTrackFlush()
	}

	return nil
}

func (s *server) installCNI() {
	install := deliver.NewInstaller(`/app`)
	go func() {
		if err := install.Run(context.TODO(), s.cniReady); err != nil {
			log.Error().Err(err)
			close(s.cniReady)
		}
		if err := install.Cleanup(); err != nil {
			log.Error().Msgf("Failed to clean up CNI: %v", err)
		}
	}()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
		<-ch
		if err := install.Cleanup(); err != nil {
			log.Error().Msgf("Failed to clean up CNI: %v", err)
		}
	}()
}

func (s *server) Stop() {
	log.Info().Msg("cni-server stop ...")
	close(s.stop)
}
