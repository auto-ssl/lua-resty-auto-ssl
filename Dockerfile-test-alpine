FROM openresty/openresty:1.13.6.2-2-alpine-fat

RUN mkdir /app
WORKDIR /app

COPY Makefile /app/Makefile
RUN make install-test-deps-apk
RUN make install-test-deps

COPY . /app
