Name:           pkm
Version:        0.1.0
Release:        1%{?dist}
Summary:        PKI Manager for YubiHSM2

License:        ASL 2.0
URL:            https://copr.fedorainfracloud.org/coprs/phillipleblanc/pkm/
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.gz

BuildRequires:  cargo
BuildRequires:  rust-packaging
BuildRequires:  pkgconfig
BuildRequires:  libusb1-devel

Requires:       openssl

%description
pkm is a CLI for managing a YubiHSM2-backed CA and issuing TLS leaf certificates.
It stores CA keys on the HSM and wraps leaf private keys at rest using an HSM wrap key.

%prep
%autosetup -n %{name}-%{version} -a1
%cargo_prep -v vendor

%build
%cargo_build

%install
%cargo_install

%files
%license LICENSE
%{_bindir}/pkm

%changelog
* Thu Jan 01 2026 Phillip LeBlanc <phillip@leblanc.tech> - 0.1.0-1
- Initial package
