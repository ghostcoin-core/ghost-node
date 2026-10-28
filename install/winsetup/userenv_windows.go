// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// userEnvPath is the current user's environment, under HKEY_CURRENT_USER.
const userEnvPath = `Environment`

// registryEnv is the current user's environment in the registry, which
// Windows gives every program started at login.
type registryEnv struct{}

func systemUserEnv() userEnv { return registryEnv{} }

func (registryEnv) Get(name string) (string, bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, userEnvPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (registryEnv) Set(name, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, userEnvPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}
