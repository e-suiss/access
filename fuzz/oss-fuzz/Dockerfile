# SA-T9, OP-159 m.3 (cc)
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
RUN git clone --depth 1 https://github.com/e-suiss/access access
WORKDIR $SRC/access
COPY build.sh $SRC/
