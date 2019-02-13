FROM node:10-alpine
WORKDIR /usr/src/app
COPY ./package*.json ./
COPY ./.npmrc ./
RUN npm install --only=production
COPY ./src/ ./src
CMD [ "node", "./src/index.js" ]
