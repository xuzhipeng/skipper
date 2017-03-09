FROM registry.opensource.zalan.do/stups/alpine:latest
MAINTAINER Skipper Maintainers <team-pathfinder@zalando.de>
RUN mkdir -p /usr/bin
ADD skipper eskip /usr/bin/
ENV PATH $PATH:/usr/bin
CMD ["/usr/bin/skipper"]
