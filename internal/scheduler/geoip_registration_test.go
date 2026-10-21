package scheduler

import (
	"testing"

	"github.com/ishizakahiroshi/heartdesk/internal/config"
)

// GeoIP を使わない既定構成（DB パスも IPinfo トークンも空）では、update_geoip_db を登録しない。
// 登録したままだと起動時と毎日「not configured」エラーになる。
func TestUpdateGeoIPDBNotRegisteredWithoutGeoIPConfig(t *testing.T) {
	for name, cfg := range map[string]*config.SchedulerConfig{
		"空の設定":        {},
		"空白だけの設定":     {GeoIPDBPath: "  ", GeoIPToken: "\t"},
		"DB 更新間隔だけある": {UpdateGeoIPDBInterval: 3600},
	} {
		s := NewScheduler(cfg, nil)
		if _, ok := s.jobs["update_geoip_db"]; ok {
			t.Errorf("%s: GeoIP の設定が無いのに update_geoip_db が登録された", name)
		}
		if _, ok := s.jobs["collect_resources"]; !ok {
			t.Errorf("%s: 他のジョブまで消えている", name)
		}
	}
}

func TestUpdateGeoIPDBRegisteredWithGeoIPConfig(t *testing.T) {
	for name, cfg := range map[string]*config.SchedulerConfig{
		"DB パスとトークン":             {GeoIPDBPath: "/var/lib/heartdesk/geoip/ipinfo_lite.mmdb", GeoIPToken: "test-token"},
		"DB パスだけ（設定漏れをエラーで知らせる）": {GeoIPDBPath: "/var/lib/heartdesk/geoip/ipinfo_lite.mmdb"},
		"トークンだけ（設定漏れをエラーで知らせる）":  {GeoIPToken: "test-token"},
	} {
		s := NewScheduler(cfg, nil)
		if _, ok := s.jobs["update_geoip_db"]; !ok {
			t.Errorf("%s: update_geoip_db が登録されていない", name)
		}
	}
}

// cfg が nil のときは従来どおり全ジョブを登録する（設定を読めない呼び出しで勝手に消さない）。
func TestUpdateGeoIPDBRegisteredWhenConfigIsNil(t *testing.T) {
	s := NewScheduler(nil, nil)
	if _, ok := s.jobs["update_geoip_db"]; !ok {
		t.Error("cfg=nil で update_geoip_db が登録されていない")
	}
}
