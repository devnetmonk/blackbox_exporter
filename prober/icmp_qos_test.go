package prober

import (
	"blackbox_exporter/config"
	"context"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeICMPQoS(t *testing.T) {
	logger := log.NewNopLogger()
	sc := config.SafeConfig{C: &config.Config{}}
	configFile := "../example_qos.yml"
	if err := sc.ReloadConfig(configFile, logger); err != nil {
		_ = level.Error(logger).Log("msg", "Error loading config", "err", err)
		t.Fatal(err)
		return
	}
	conf := sc.C
	// sc.Unlock()

	ctx := context.Background()
	type args struct {
		target       string
		moduleName   string
		httpOverride bool
		overrideURI  string
		timeout      int
		count        int
		packetSize   int
		ttl          int
		interval     int
	}
	tests := []struct {
		name        string
		args        args
		wantSuccess bool
	}{
		{
			name: "default",
			args: args{
				target:       "8.8.8.8",
				httpOverride: false,
			},
			wantSuccess: true,
		},
		{
			name: "default - Count",
			args: args{
				target:       "8.8.8.8",
				httpOverride: false,
				count:        100,
			},
			wantSuccess: true,
		},
		{
			name: "default - TTL",
			args: args{
				target:       "8.8.8.8",
				httpOverride: false,
				ttl:          64,
			},
			wantSuccess: true,
		},
		{
			name: "default - Timeout",
			args: args{
				target:       "8.8.8.8",
				httpOverride: false,
				timeout:      1200,
			},
			wantSuccess: true,
		},
		{
			name: "default - Interval",
			args: args{
				target:       "8.8.8.8",
				httpOverride: false,
				interval:     10,
			},
			wantSuccess: true,
		},
		{
			name: "default - Packet Size",
			args: args{
				target:       "8.8.8.8",
				httpOverride: false,
				packetSize:   64,
			},
			wantSuccess: true,
		},
		{
			name: "Bad - UnCountable",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?count=banyak",
			},
			wantSuccess: false,
		},
		{
			name: "Bad - BigCount",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?count=100000",
			},
			wantSuccess: false,
		},
		{
			name: "Bad - NoCount",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?count=0",
			},
			wantSuccess: false,
		},
		{
			name: "bad - Not Interval",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?interval=asf",
			},
			wantSuccess: false,
		},
		{
			name: "bad - Not a Packet",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?packet_size=asf",
			},
			wantSuccess: false,
		},
		{
			name: "bad - Packet Oversize",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?packet_size=15000",
			},
			wantSuccess: false,
		},
		{
			name: "bad - Packet Undersized",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?packet_size=15",
			},
			wantSuccess: false,
		},
		{
			name: "bad - override ttl",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?ttl=asf",
			},
			wantSuccess: false,
		},
		{
			name: "bad - Can Not Timeout",
			args: args{
				target:       "8.8.8.8",
				httpOverride: true,
				overrideURI:  "/?timeout=asf",
			},
			wantSuccess: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var registry *prometheus.Registry
			registry = prometheus.NewRegistry()
			var icmpQoSProbeConfig config.ICMPQOSProbe

			moduleName := "icmp_qos_example"
			if tt.args.moduleName != "" {
				moduleName = tt.args.moduleName
			}
			module, _ := conf.Modules[moduleName]

			icmpQoSProbeConfig = module.ICMPQOS

			if tt.args.timeout > 0 {
				icmpQoSProbeConfig.Timeout = tt.args.timeout
			}
			if tt.args.count > 0 {
				icmpQoSProbeConfig.Count = tt.args.count
			}
			if tt.args.packetSize > 0 {
				icmpQoSProbeConfig.PacketSize = tt.args.packetSize
			}
			if tt.args.ttl > 0 {
				icmpQoSProbeConfig.TTL = tt.args.ttl
			}
			if tt.args.interval > 0 {
				icmpQoSProbeConfig.Interval = tt.args.interval
			}

			module = config.Module{
				ICMPQOS: icmpQoSProbeConfig,
			}

			var r *http.Request
			if tt.args.httpOverride {
				r = httptest.NewRequest(http.MethodGet, tt.args.overrideURI, nil)
			} else {
				r = httptest.NewRequest(http.MethodGet, "/", nil)
			}

			if gotSuccess := ProbeICMPQoS(ctx, tt.args.target, module, registry, logger, r); gotSuccess != tt.wantSuccess {
				t.Errorf("ProbeICMPQoS() = %v, want %v", gotSuccess, tt.wantSuccess)
			}
		})
	}
}
