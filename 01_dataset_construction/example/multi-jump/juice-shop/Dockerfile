FROM docker.pengyihao.top/library/ubuntu:22.04
USER root

RUN apt update
RUN apt-get install -y curl git build-essential

COPY --from=ins-node:pyh-v22 /usr/local /usr/local

# install juice shop
WORKDIR /root
# COPY ./juice-shop-17.1.1_node22_linux_x64.tgz /root/
# RUN tar -xzf /root/juice-shop-17.1.1_node22_linux_x64.tgz
# Extract through a pipe; no file needs to be removed because it is not saved
RUN curl -L "https://github.com/juice-shop/juice-shop/releases/download/v17.1.1/juice-shop-17.1.1_node22_linux_x64.tgz" | tar -xz
WORKDIR /root/juice-shop_17.1.1
# Remove the Node version limit
RUN sed -i '/"engines": {/,/},/d' package.json
RUN sed -i 's/"start": "node /"start": "node --max-old-space-size=16384 /' package.json

RUN sed -i '/const app = express();/a \
app.use((req, res, next) => {\n\
    console.log({\n\
        method: req.method,\n\
        url: req.url,\n\
        headers: req.headers,\n\
        body: req.body,\n\
        ip: req.ip,\n\
    });\n\
    next();\n\
});\n' build/server.js

# Enable all challenges
COPY challenges.yml data/static/
RUN mkdir /applog

CMD ["/bin/bash", "-c", "npm start 2>&1 > /applog/app.log"]
