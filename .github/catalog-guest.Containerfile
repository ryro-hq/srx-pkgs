
# Appended to the pinned core guest Containerfile. glibc's gettext regression
# builds its message catalog with the distro-authenticated msgfmt tool.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gettext \
    && rm -rf /var/lib/apt/lists/*
