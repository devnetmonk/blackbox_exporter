// Copyright 2024 Arieditya Pr.dH [for netmonk.id]
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"blackbox_exporter/config"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	ping "github.com/prometheus-community/pro-bing"
	"github.com/prometheus/client_golang/prometheus"
)

func ProbeICMPQoS(_ context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger, r *http.Request) (success bool) {
	var (
		// durations
		startDuration time.Time
		endDuration   time.Time
		totalDuration time.Duration

		// jitters
		prevTime  time.Duration
		jitter    time.Duration
		jitterSum time.Duration
		jitterMax time.Duration
		jitterMin time.Duration

		rttMapping map[int]time.Duration
		seqMax     int
	)
	rttMapping = make(map[int]time.Duration)

	// start duration benchmark
	startDuration = time.Now()

	var probeResponseError = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_break_error_code",
		Help: "Exception has been raised on probe",
	}, []string{"error_code", "error_message", "error_value"})

	// Registering OpenMetrics Data
	var probeQoSDurationSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_qos_duration_seconds",
		Help: "Total Durations of the pinger executions (in seconds)",
	})

	var probeQosLatencyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_qos_latency",
		Help: "Probe QoS Latency Gauge (all are in milliseconds)",
	}, []string{"aggregate"})
	for _, lv := range []string{"total", "min", "max", "avg", "standard_deviation"} {
		probeQosLatencyGauge.WithLabelValues(lv)
	}

	var probeQoSPacketLoss = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_qos_packet_loss_gauge",
		Help: "Probe QoS Latency Packet Loss",
	}, []string{"total"})
	for _, lv := range []string{"sent", "received", "loss", "loss_percentage"} {
		probeQoSPacketLoss.WithLabelValues(lv)
	}

	var probeQoSJitterGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_qos_jitter_gauge",
		Help: "Probe QoS Jitter Gauge (all are in microseconds)",
	}, []string{"aggregate"})
	for _, lv := range []string{"total_diff", "max_diff", "min_diff"} {
		probeQoSJitterGauge.WithLabelValues(lv)
	}

	var probeQoSJitter = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_qos_jitter",
		Help: "Jitter Calculations and Aggregates (in microseconds)",
	})

	var probeQoSPacketCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_qos_packet_count",
		Help: "Total number of tested data to be sent to target",
	})

	_ = level.Debug(logger).Log("msg", "Set Pinger")
	pinger, err := ping.NewPinger(target)
	if err != nil {
		_ = level.Error(logger).Log("msg", "set pinger failed", "err", err)
		return false
	}

	if onWindows() {
		pinger.SetPrivileged(true)
	}

	pinger.Count = module.ICMPQOS.Count
	pinger.Size = module.ICMPQOS.PacketSize // in bytes
	pinger.Interval = time.Duration(module.ICMPQOS.Interval) * time.Millisecond
	pinger.Timeout = time.Duration(module.ICMPQOS.Timeout) * time.Millisecond
	pinger.TTL = module.ICMPQOS.TTL
	//maxTimeout = float64(pinger.Timeout) / perThousand

	// OVERRIDE with Query String
	params := r.URL.Query()
	if cnt := params.Get("count"); cnt != "" {
		if pinger.Count, err = strconv.Atoi(cnt); err != nil {
			errLabel := prometheus.Labels{
				"error_code":    "100011",
				"error_message": "cannot override 'count' parameters with non-numeric value",
				"error_value":   cnt,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		}
		if pinger.Count < 1 {
			errLabel := prometheus.Labels{
				"error_code":    "100012",
				"error_message": "parameter 'count' below limit",
				"error_value":   cnt,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		}
		if pinger.Count > 1000 {
			errLabel := prometheus.Labels{
				"error_code":    "100013",
				"error_message": "parameter 'count' exceed limits",
				"error_value":   cnt,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		}
	}

	if size := params.Get("packet_size"); size != "" {
		if pinger.Size, err = strconv.Atoi(size); err != nil {
			errLabel := prometheus.Labels{
				"error_code":    "100021",
				"error_message": "cannot override 'packet_size' parameters with non-numeric value",
				"error_value":   size,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		}
		if pinger.Size < 18 {
			errLabel := prometheus.Labels{
				"error_code":    "100022",
				"error_message": "parameter 'packet_size' below limit",
				"error_value":   size,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		}
		if pinger.Size > 1460 {
			errLabel := prometheus.Labels{
				"error_code":    "100023",
				"error_message": "parameter 'packet_size' exceed limits",
				"error_value":   size,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		}
	}

	var itvl int
	if interval := params.Get("interval"); interval != "" {
		if itvl, err = strconv.Atoi(interval); err != nil {
			errLabel := prometheus.Labels{
				"error_code":    "100031",
				"error_message": "cannot override 'interval' parameters with non-numeric value",
				"error_value":   interval,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		} else {
			pinger.Interval = time.Duration(itvl) * time.Millisecond
		}
	}

	var time2live int
	if ttl := params.Get("ttl"); ttl != "" {
		if time2live, err = strconv.Atoi(ttl); err != nil {
			errLabel := prometheus.Labels{
				"error_code":    "100041",
				"error_message": "cannot override 'ttl' parameters with non-numeric value",
				"error_value":   ttl,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		} else {
			pinger.TTL = time2live
		}
	}

	var timeout int
	if to := params.Get("timeout"); to != "" {
		if timeout, err = strconv.Atoi(to); err != nil {
			errLabel := prometheus.Labels{
				"error_code":    "100051",
				"error_message": "cannot override 'timeout' parameters with non-numeric value",
				"error_value":   to,
			}
			probeResponseError.With(errLabel).Add(1)
			registry.MustRegister(probeResponseError)
			return false
		} else {
			pinger.Timeout = time.Duration(timeout) * time.Millisecond
		}
	}

	registry.MustRegister(probeQoSDurationSeconds)
	registry.MustRegister(probeQosLatencyGauge)
	registry.MustRegister(probeQoSPacketLoss)
	registry.MustRegister(probeQoSJitter)
	registry.MustRegister(probeQoSJitterGauge)
	registry.MustRegister(probeQoSPacketCount)

	pinger.OnRecvError = func(err error) {
		jitter = prevTime
		jitter = pinger.Timeout - prevTime
		if jitter < 0 {
			jitter = -jitter
		}
		jitterSum += jitter
		prevTime = pinger.Timeout
		jitterMax = prevTime
	}
	pinger.OnRecv = func(pkt *ping.Packet) {
		rttMapping[pkt.Seq] = pkt.Rtt
		if pkt.Seq > seqMax {
			seqMax = pkt.Seq
		}
		// jitter (in microseconds)
		jitter = pkt.Rtt - prevTime
		if jitter < 0 {
			jitter = -jitter
		}
		if jitter > jitterMax {
			jitterMax = jitter
		}
		if jitter != 0 && jitter < jitterMin {
			jitterMin = jitter
		}
		jitterSum += jitter

		prevTime = pkt.Rtt
	}

	pinger.OnFinish = func(s *ping.Statistics) {
		var i int
		var jitterCount int64
		for i = 0; i <= seqMax; i++ {

			if i == 0 {
				jitterSum = 0
				jitterMax = 0
				jitterMin = pinger.Timeout
			}
			if rtt, ok := rttMapping[i]; ok {
				if i == 0 {
					prevTime = rtt
					continue
				}
				jitterCount++
				jitter = prevTime - rtt
				if jitter < 0 {
					jitter = -jitter
				}
				jitterSum += jitter
				if jitter < jitterMin {
					jitterMin = jitter
				}
				if jitter > jitterMax {
					jitterMax = jitter
				}
				prevTime = rtt
			}
		}

		// probe_qos_packet_count
		probeQoSPacketCount.Set(float64(pinger.Count))

		probeQoSJitter.Set(float64(jitterSum.Nanoseconds()) / float64(jitterCount*1000))
		probeQoSJitterGauge.WithLabelValues("total_diff").Add(float64(jitterSum.Nanoseconds()) / 1000)
		probeQoSJitterGauge.WithLabelValues("max_diff").Add(float64(jitterMax.Nanoseconds()) / 1000)
		probeQoSJitterGauge.WithLabelValues("min_diff").Add(float64(jitterMin.Nanoseconds()) / 1000)

		probeQoSPacketLoss.WithLabelValues("sent").Add(float64(s.PacketsSent))
		probeQoSPacketLoss.WithLabelValues("received").Add(float64(s.PacketsRecv))
		probeQoSPacketLoss.WithLabelValues("loss").Add(float64(s.PacketsSent - s.PacketsRecv))
		probeQoSPacketLoss.WithLabelValues("loss_percentage").Add(s.PacketLoss)

		var probeQosLatencyGaugeTotal time.Duration
		for _, rtt := range s.Rtts {
			probeQosLatencyGaugeTotal += rtt
		}
		probeQosLatencyGauge.WithLabelValues("total").Add(probeQosLatencyGaugeTotal.Seconds() * 1000)
		probeQosLatencyGauge.WithLabelValues("max").Add(s.MaxRtt.Seconds() * 1000)
		probeQosLatencyGauge.WithLabelValues("min").Add(s.MinRtt.Seconds() * 1000)
		probeQosLatencyGauge.WithLabelValues("avg").Add(s.AvgRtt.Seconds() * 1000)
		probeQosLatencyGauge.WithLabelValues("standard_deviation").Add(s.StdDevRtt.Seconds() * 1000)

		// Logging the result
		_ = level.Info(logger).Log("msg", "ICMP Gauge summary",
			// packet loss
			"packet_sent", s.PacketsSent,
			"packet_received", s.PacketsRecv,
			"packet_loss", s.PacketsSent-s.PacketsRecv,
			"packet_loss_percentage", s.PacketLoss,

			// latency
			"latency_total", probeQosLatencyGaugeTotal,
			"latency_max", s.MaxRtt,
			"latency_min", s.MinRtt,
			"latency_avg", s.AvgRtt,
			"latency_std_deviation", s.StdDevRtt,

			// jitters
			"jitters", jitter,
			"jitter_max", jitterMax,
			"jitter_min", jitterMin,
			"jitter_total", jitterSum,
		)

		// probe_duration_seconds
		endDuration = time.Now()
		totalDuration = endDuration.Sub(startDuration)
		probeQoSDurationSeconds.Set(totalDuration.Seconds())
		_ = level.Info(logger).Log("msg", "ICMP Execution duration", "duration", totalDuration.Seconds())
	}

	err = pinger.Run()
	if err != nil {
		_ = level.Error(logger).Log("msg", "Pinger failed to run", "err", err)
		return false
	}

	return true
}
