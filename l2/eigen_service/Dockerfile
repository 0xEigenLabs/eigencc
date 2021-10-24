FROM node:12.22.5-alpine3.14

MAINTAINER Eigen

EXPOSE 3000

WORKDIR /app
COPY . /app
RUN yarn build

RUN npm install forever -g && npm install

CMD ["forever", "build/src/app.js"]
