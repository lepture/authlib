.PHONY: tests clean clean-pyc clean-build docs

GEMFURY_AUTH_TOKEN := ${GEMFURY_AUTH_TOKEN}

# distribution details
VERSION := $(shell awk '$$1 == "version" {print $$NF}' ./authlib/consts.py)
OS := none
CPU_ARCH = any

help:
	@echo "authlib Makefile Help:\n"\
	"clean:  Remove all cache and wheel packages.\n"\
	"build:  Build authlib wheel package via setup.py.\n"\
	"version:  Show current authlib version.\n"\
	"publish:  Upload the package in dist directory that matches current authlib version.\n"\
	" VERSION Specify another version to upload (If there is one avaliable). "

clean: clean-build clean-pyc clean-docs clean-tox

tests:
	@TOXENV=py,flask,django,coverage tox

clean-build:
	@rm -fr build/
	@rm -fr dist/
	@rm -fr *.egg
	@rm -fr *.egg-info


clean-pyc:
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +
	@find . -name '__pycache__' -exec rm -fr {} +

clean-docs:
	@rm -fr  docs/_build

clean-tox:
	@rm -rf .tox/

docs:
	@$(MAKE) -C docs html

build: clean
	python3 setup.py bdist_wheel

version:
	@echo $(VERSION)

publish: override VERSION := $(if $(VERSION),$(VERSION),)
publish: WHEEL_FILENAME := deming_core-$(VERSION)-py3-$(OS)-$(CPU_ARCH).whl
publish:
	curl -F package=@dist/$(WHEEL_FILENAME) https://$(GEMFURY_AUTH_TOKEN)@push.fury.io/quartic-ai/
