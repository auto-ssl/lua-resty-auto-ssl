FROM openresty/openresty:1.13.6.2-2-bionic

RUN mkdir /app
WORKDIR /app

COPY Makefile /app/Makefile
RUN make install-test-deps-apt
RUN make install-test-deps

COPY . /app
