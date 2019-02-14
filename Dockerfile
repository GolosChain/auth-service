FROM node:10-alpine
WORKDIR /usr/src/app
COPY .npmrc ./
COPY package.json ./
COPY package-lock.json ./
RUN npm install --only=production
COPY ./src/ ./src
CMD [ "node", "./src/index.js" ]
