package proxy

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func appendTestMMDBString(buffer []byte, value string) []byte {
	if len(value) >= 29 {
		panic("test MMDB string is too long")
	}
	buffer = append(buffer, byte(2<<5|len(value)))
	return append(buffer, value...)
}

func appendTestMMDBUint32(buffer []byte, value uint32) []byte {
	buffer = append(buffer, byte(6<<5|4))
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(buffer, encoded[:]...)
}

// buildTestMMDB constructs a valid, metadata-only MMDB. A zero-node tree is
// sufficient for testing successful loading and metadata without shipping data.
func buildTestMMDB(buildEpoch uint32) []byte {
	metadata := []byte{byte(7<<5 | 7)}
	for _, item := range []struct {
		key   string
		value uint32
	}{
		{"binary_format_major_version", 2},
		{"binary_format_minor_version", 0},
		{"build_epoch", buildEpoch},
		{"ip_version", 4},
		{"node_count", 0},
		{"record_size", 24},
	} {
		metadata = appendTestMMDBString(metadata, item.key)
		metadata = appendTestMMDBUint32(metadata, item.value)
	}
	metadata = appendTestMMDBString(metadata, "database_type")
	metadata = appendTestMMDBString(metadata, "Test")

	data := make([]byte, 16) // empty search tree plus data-section separator
	data = append(data, []byte("\xab\xcd\xefMaxMind.com")...)
	return append(data, metadata...)
}

func writeGeoStatusTestFile(t *testing.T, path string, data []byte, modTime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("set %s modtime: %v", path, err)
	}
}

func TestGeoIPDataStatusLoadedSourcesAndTimes(t *testing.T) {
	dir := t.TempDir()
	countryPath := filepath.Join(dir, "geoip.mmdb")
	cityPath := filepath.Join(dir, "geoip_city.mmdb")
	asnPath := filepath.Join(dir, "geoip_asn.mmdb")
	oldXDBPath := filepath.Join(dir, "ip2region.xdb")
	xdbPath := filepath.Join(dir, "ip2region_v4.xdb")

	const buildEpoch = uint32(1700000000)
	countryModTime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	cityModTime := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	xdbModTime := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	writeGeoStatusTestFile(t, countryPath, buildTestMMDB(buildEpoch), countryModTime)
	// A zero build epoch must still expose the loaded file's modtime fallback.
	writeGeoStatusTestFile(t, cityPath, buildTestMMDB(0), cityModTime)
	writeGeoStatusTestFile(t, asnPath, []byte("not an mmdb"), cityModTime)
	// An invalid preferred file must not hide the valid fallback or appear in status.
	writeGeoStatusTestFile(t, oldXDBPath, []byte("not an xdb"), xdbModTime.Add(time.Hour))
	writeGeoStatusTestFile(t, xdbPath, buildTestXDB(t, true), xdbModTime)

	g := NewGeoIP(dir)
	t.Cleanup(func() {
		if g.country != nil {
			_ = g.country.Close()
		}
		if g.city != nil {
			_ = g.city.Close()
		}
		if g.asn != nil {
			_ = g.asn.Close()
		}
	})
	statuses := g.DataStatus()
	if len(statuses) != 3 {
		t.Fatalf("DataStatus returned %d sources, want country/city/xdb: %+v", len(statuses), statuses)
	}
	byPath := make(map[string]GeoDataStatus, len(statuses))
	for _, status := range statuses {
		byPath[status.Path] = status
	}
	if _, ok := byPath[asnPath]; ok {
		t.Fatalf("invalid ASN database appeared in DataStatus: %+v", byPath[asnPath])
	}
	if _, ok := byPath[oldXDBPath]; ok {
		t.Fatalf("unloaded preferred XDB appeared in DataStatus: %+v", byPath[oldXDBPath])
	}

	country := byPath[countryPath]
	if country.Kind != "mmdb" || !country.BuildTime.Equal(time.Unix(int64(buildEpoch), 0)) ||
		!country.ModTime.Equal(countryModTime) {
		t.Fatalf("country status = %+v", country)
	}
	city := byPath[cityPath]
	if city.Kind != "mmdb" || !city.BuildTime.IsZero() || !city.ModTime.Equal(cityModTime) {
		t.Fatalf("city status = %+v", city)
	}
	xdb := byPath[xdbPath]
	if xdb.Kind != "xdb" || !xdb.BuildTime.IsZero() || !xdb.ModTime.Equal(xdbModTime) {
		t.Fatalf("effective XDB status = %+v", xdb)
	}

	statuses[0].Path = "caller mutation"
	if g.DataStatus()[0].Path == "caller mutation" {
		t.Fatal("DataStatus returned its internal slice")
	}
	if got := NewGeoIP(t.TempDir()).DataStatus(); len(got) != 0 {
		t.Fatalf("empty GeoIP DataStatus = %+v", got)
	}
}
