
# Appended to the pinned core guest Containerfile. glibc's gettext regression
# builds its message catalog with the distro-authenticated msgfmt tool.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gettext \
    && . /etc/os-release \
    && if [ "$ID" = debian ]; then \
         test "$VERSION_CODENAME" = forky \
         && apt-get install -y --no-install-recommends \
            musl=1.2.6-2 musl-dev=1.2.6-2 musl-tools=1.2.6-2; \
       fi \
    && rm -rf /var/lib/apt/lists/*
