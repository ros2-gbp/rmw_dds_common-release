%bcond_without tests
%bcond_without weak_deps

%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')
%global __provides_exclude_from ^/opt/ros/rolling/.*$
%global __requires_exclude_from ^/opt/ros/rolling/.*$

Name:           ros-rolling-rmw-dds-common
Version:        1.2.0
Release:        1%{?dist}%{?release_suffix}
Summary:        ROS rmw_dds_common package

License:        Apache License 2.0
Source0:        %{name}-%{version}.tar.gz

Requires:       ros-rolling-rcpputils
Requires:       ros-rolling-rcutils
Requires:       ros-rolling-rmw
Requires:       ros-rolling-rosidl-default-runtime
Requires:       ros-rolling-rosidl-runtime-cpp
Requires:       ros-rolling-ros-workspace
BuildRequires:  ros-rolling-ament-cmake
BuildRequires:  ros-rolling-ament-cmake-gmock
BuildRequires:  ros-rolling-ament-lint-auto
BuildRequires:  ros-rolling-ament-lint-common
BuildRequires:  ros-rolling-osrf-testing-tools-cpp
BuildRequires:  ros-rolling-performance-test-fixture
BuildRequires:  ros-rolling-rcpputils
BuildRequires:  ros-rolling-rcutils
BuildRequires:  ros-rolling-rmw
BuildRequires:  ros-rolling-rosidl-default-generators
BuildRequires:  ros-rolling-rosidl-runtime-cpp
BuildRequires:  ros-rolling-ros-workspace
BuildRequires:  ros-rolling-rosidl-typesupport-connext-c
BuildRequires:  ros-rolling-rosidl-typesupport-connext-cpp
BuildRequires:  ros-rolling-rosidl-typesupport-fastrtps-c
BuildRequires:  ros-rolling-rosidl-typesupport-fastrtps-cpp
Provides:       %{name}-devel = %{version}-%{release}
Provides:       %{name}-doc = %{version}-%{release}
Provides:       %{name}-runtime = %{version}-%{release}
Provides:       ros-rolling-rosidl-interface-packages(member)

%if 0%{?with_weak_deps}
Supplements:    ros-rolling-rosidl-interface-packages(all)
%endif

%description
Define a common interface between DDS implementations of ROS middleware.

%prep
%autosetup

%build
# In case we're installing to a non-standard location, look for a setup.sh
# in the install tree and source it.  It will set things like
# CMAKE_PREFIX_PATH, PKG_CONFIG_PATH, and PYTHONPATH.
if [ -f "/opt/ros/rolling/setup.sh" ]; then . "/opt/ros/rolling/setup.sh"; fi
mkdir -p obj-%{_target_platform} && cd obj-%{_target_platform}
%cmake3 \
    -UINCLUDE_INSTALL_DIR \
    -ULIB_INSTALL_DIR \
    -USYSCONF_INSTALL_DIR \
    -USHARE_INSTALL_PREFIX \
    -ULIB_SUFFIX \
    -DCMAKE_INSTALL_PREFIX="/opt/ros/rolling" \
    -DAMENT_PREFIX_PATH="/opt/ros/rolling" \
    -DCMAKE_PREFIX_PATH="/opt/ros/rolling" \
    -DSETUPTOOLS_DEB_LAYOUT=OFF \
    ..

%make_build

%install
# In case we're installing to a non-standard location, look for a setup.sh
# in the install tree and source it.  It will set things like
# CMAKE_PREFIX_PATH, PKG_CONFIG_PATH, and PYTHONPATH.
if [ -f "/opt/ros/rolling/setup.sh" ]; then . "/opt/ros/rolling/setup.sh"; fi
%make_install -C obj-%{_target_platform}

%if 0%{?with_tests}
%check
# Look for a Makefile target with a name indicating that it runs tests
TEST_TARGET=$(%__make -qp -C obj-%{_target_platform} | sed "s/^\(test\|check\):.*/\\1/;t f;d;:f;q0")
if [ -n "$TEST_TARGET" ]; then
# In case we're installing to a non-standard location, look for a setup.sh
# in the install tree and source it.  It will set things like
# CMAKE_PREFIX_PATH, PKG_CONFIG_PATH, and PYTHONPATH.
if [ -f "/opt/ros/rolling/setup.sh" ]; then . "/opt/ros/rolling/setup.sh"; fi
%make_build -C obj-%{_target_platform} $TEST_TARGET || echo "RPM TESTS FAILED"
else echo "RPM TESTS SKIPPED"; fi
%endif

%files
/opt/ros/rolling

%changelog
* Mon Mar 08 2021 Ivan Paunovic <ivanpauno@ekumenlabs.com> - 1.2.0-1
- Autogenerated by Bloom

