#!/usr/bin/env bash
docker build . -t everyclass-identity:$(git describe --tag)