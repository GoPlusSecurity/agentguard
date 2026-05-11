FROM node:22-slim

WORKDIR /workspace

RUN npm install -g @goplus/agentguard
RUN agentguard init --agent openclaw

COPY plugin.ts ./plugin.ts

CMD ["node", "-e", "console.log('AgentGuard OpenClaw demo ready. Mount your OpenClaw workspace and register plugin.ts.')"]
