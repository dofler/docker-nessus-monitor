FROM stevemcgrath/nessus_monitor:latest

ENV MONITOR_NETWORKS "0.0.0.0/0"
ENV MONITOR_INTERFACE "eth1"
ENV LICENSE ""
ENV DOFLER_ACCESS ""
ENV DOFLER_SECRET ""
ENV DOFLER_ADDRESS ""

COPY supervisor.conf /etc
COPY event_poster.py /usr/bin

RUN yum -y install python-requests                                                          \
    && yum clan all                                                                         \
    && chmod 700 /etc/supervisor.conf                                                       \
    && chmod 755 /usr/bin/event_poster.py                                                   \
    && /opt/pvs/bin/pvs --config "Realtime Syslog Server List" "127.0.0.1:9514:0:0"         \
    && /opt/pvs/bin/pvs --config "Vulnerability Syslog Server List" "127.0.0.1:9514:0:0"

VOLUME /opt/pvs/var/pvs
EXPOSE 8835

CMD ["/usr/bin/supervisord", "-nc", "/etc/supervisor.conf"]