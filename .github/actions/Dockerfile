FROM voidlinux/voidlinux-musl

RUN xbps-install -Suy
RUN xbps-install -uy
RUN xbps-install -y base-devel bearssl-devel

ENTRYPOINT ["sh", "-c", "./configure && make all && RATELIMIT=1 make check check-net"]
