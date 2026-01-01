NAME := pkm
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
RPM_TOPDIR := $(HOME)/rpmbuild
TARBALL := $(RPM_TOPDIR)/SOURCES/$(NAME)-$(VERSION).tar.gz
VENDOR_DIR := vendor
VENDOR_TARBALL := $(RPM_TOPDIR)/SOURCES/$(NAME)-$(VERSION)-vendor.tar.gz
TAR_EXCLUDES := --exclude-vcs --exclude=.jj --exclude=target --exclude=vendor --exclude=rpmbuild --exclude=copr-logs*
COPR_REPO ?= phillipleblanc/pkm

.PHONY: srpm
srpm:
	mkdir -p $(RPM_TOPDIR)/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
	rm -rf $(VENDOR_DIR)
	cargo vendor $(VENDOR_DIR)
	tar -czf $(VENDOR_TARBALL) $(VENDOR_DIR)
	rm -rf $(VENDOR_DIR)
	tar -czf $(TARBALL) $(TAR_EXCLUDES) --transform "s,^\\./,$(NAME)-$(VERSION)/," .
	cp $(NAME).spec $(RPM_TOPDIR)/SPECS/$(NAME).spec
	rpmbuild -bs $(RPM_TOPDIR)/SPECS/$(NAME).spec

copr-build: srpm
	copr-cli build $(COPR_REPO) $(RPM_TOPDIR)/SRPMS/$(NAME)-$(VERSION)-*.src.rpm
