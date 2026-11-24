FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/swarmcontrol
RUN groupadd --gid 10001 swarm && useradd --uid 10001 --gid swarm --no-create-home swarm && install -d -m 0700 -o swarm -g swarm /data /backups
COPY --chown=10001:10001 backend backend
COPY --chown=10001:10001 agent agent
COPY --chown=10001:10001 integrations integrations
COPY --chown=10001:10001 frontend frontend
COPY --chown=10001:10001 deploy deploy
COPY --chown=10001:10001 LICENSE README.md ./
USER 10001:10001
EXPOSE 8790
CMD ["python", "deploy/start_console.py"]
