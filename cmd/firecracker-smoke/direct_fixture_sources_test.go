package main

import "testing"

func TestDirectFixtureSourceMapRejectsAnyAuthorityPathExceptTheReviewedOne(t *testing.T) {
	if _, err := loadDirectFixtureSourceMap("/tmp/fixture-map.json", directFixtureLockPath); err == nil || err.Error() != "direct fixture source map does not match the reviewed authority" {
		t.Fatalf("loadDirectFixtureSourceMap() error = %v, want reviewed-authority refusal", err)
	}
}

func TestValidDirectFixturePathIsConfinedToHomeServerFixtureAuthority(t *testing.T) {
	if validDirectFixturePath("/tmp/firecracker") || validDirectFixturePath(directFixtureSourceRoot) || validDirectFixturePath(directFixtureSourceRoot+"/../other") || !validDirectFixturePath(directFixtureSourceRoot+"/input/vmlinux") {
		t.Fatal("validDirectFixturePath() did not confine direct fixture source paths")
	}
}
