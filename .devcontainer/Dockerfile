# based on https://github.com/anthropics/claude-code/tree/main/.devcontainer
# and https://www.chainguard.dev/unchained/migrating-a-node-js-application-to-chainguard-images
FROM cgr.dev/chainguard/node:latest-dev

ARG CLAUDE_CODE_VERSION=latest

# Switch to root for package installation
USER root

# Install basic development tools and iptables/ipset
RUN apk update && apk add \
  less \
  git \
  procps \
  fzf \
  man-db \
  unzip \
  gnupg \
  iptables \
  ipset \
  iproute2 \
  bind-tools \
  jq \
  vim \
  wget \
  bash \
  su-exec \
  && rm -rf /var/cache/apk/*

ARG USERNAME=dev

# Create non-root user
RUN addgroup ${USERNAME} && adduser -D -G ${USERNAME} ${USERNAME}

# Ensure default dev user has access to /usr/local/share
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R ${USERNAME}:${USERNAME} /usr/local/share

# Persist bash history.
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
  && mkdir /commandhistory \
  && touch /commandhistory/.bash_history \
  && chown -R ${USERNAME} /commandhistory

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true

# Create workspace and config directories and set permissions
RUN mkdir -p /workspace /home/${USERNAME}/.claude && \
  chown -R ${USERNAME}:${USERNAME} /workspace /home/${USERNAME}/.claude

WORKDIR /workspace

# Set up non-root user
USER dev

# Install global packages
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=$PATH:/usr/local/share/npm-global/bin

# Set the default editor and visual
ENV EDITOR=vim
ENV VISUAL=vim

# Install Claude
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

# Switch back to root for firewall setup
USER root

# Set up network firewall scripts and log infrastructure
COPY scripts/ /opt/scripts/
COPY extra-whitelist.conf /opt/scripts/extra-whitelist.conf
RUN chmod +x /opt/scripts/*.sh && \
    touch /var/log/firewall.log /var/log/firewall-status.txt && \
    chmod 644 /var/log/firewall.log /var/log/firewall-status.txt

ENTRYPOINT ["/opt/scripts/entrypoint.sh"]
CMD ["sleep", "infinity"]
