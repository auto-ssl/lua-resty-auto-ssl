FROM openresty/openresty:1.13.6.2-2-centos

# Build dependencies.
RUN yum -y install make

# Dependencies for the release process.
RUN yum -y install git zip

RUN mkdir /app
WORKDIR /app

COPY Makefile /app/Makefile
RUN make install-test-deps-yum
RUN make install-test-deps

COPY . /app
