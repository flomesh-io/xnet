package controller

import (
	"github.com/go-co-op/gocron/v2"

	"github.com/flomesh-io/xnet/pkg/xnet/bpf/maps"
)

const (
	minIdleSeconds = 60
	minBatchSize   = 512
	maxBatchSize   = 10240
)

func (s *server) idleTCPConnTrackFlush(sysId maps.SysID) {
	crontab := s.flushTCPConnTrackCrontab
	idleSeconds := s.flushTCPConnTrackIdleSeconds
	batchSize := s.flushTCPConnTrackBatchSize

	if idleSeconds < minIdleSeconds {
		idleSeconds = minIdleSeconds
	}
	if batchSize < minBatchSize {
		batchSize = minBatchSize
	}
	if batchSize > maxBatchSize {
		batchSize = maxBatchSize
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start cron job to flush idle tcp conn track")
	}

	if _, err = scheduler.NewJob(
		gocron.CronJob(
			// standard cron tab parsing
			crontab,
			false,
		),
		gocron.NewTask(func() {
			s.flushIdleTCPConnTracks(sysId, idleSeconds, batchSize)
		}),
	); err != nil {
		log.Fatal().Err(err).Msg("failed to start cron job to flush idle tcp conn track")
	}
	scheduler.Start()

	defer scheduler.Shutdown()

	<-s.stop
}

func (s *server) idleUDPConnTrackFlush(sysId maps.SysID) {
	crontab := s.flushUDPConnTrackCrontab
	idleSeconds := s.flushUDPConnTrackIdleSeconds
	batchSize := s.flushUDPConnTrackBatchSize

	if idleSeconds < minIdleSeconds {
		idleSeconds = minIdleSeconds
	}
	if batchSize < minBatchSize {
		batchSize = minBatchSize
	}
	if batchSize > maxBatchSize {
		batchSize = maxBatchSize
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start cron job to flush idle udp conn track")
	}

	if _, err = scheduler.NewJob(
		gocron.CronJob(
			// standard cron tab parsing
			crontab,
			false,
		),
		gocron.NewTask(func() {
			s.flushIdleUDPConnTracks(sysId, idleSeconds, batchSize)
		}),
	); err != nil {
		log.Fatal().Err(err).Msg("failed to start cron job to flush idle udp conn track")
	}
	scheduler.Start()

	defer scheduler.Shutdown()

	<-s.stop
}

func (s *server) flushIdleTCPConnTracks(sysId maps.SysID, idleSeconds, batchSize int) {
	var err error
	items := batchSize
	for items == batchSize {
		if items, err = maps.FlushIdleTCPFlowEntries(sysId, idleSeconds, batchSize); err != nil {
			log.Error().Err(err).Msg("failed to flush idle tcp flows")
			break
		}
	}
}

func (s *server) flushIdleUDPConnTracks(sysId maps.SysID, idleSeconds, batchSize int) {
	var err error
	items := batchSize
	for items == batchSize {
		if items, err = maps.FlushIdleUDPFlowEntries(sysId, idleSeconds, batchSize); err != nil {
			log.Error().Err(err).Msg("failed to flush idle tcp flows")
			break
		}
	}
}
