| Queue Name        | Description                                          | Default Publisher           | Default Subscriber                  |
| ----------------- | ---------------------------------------------------- | --------------------------- | ----------------------------------- |
| MON.rx_frame      | Publish all frames received on 'MON'                 | dot11er.infra.rx_frame      |                                     |
| MON.tx_frame      | Transmit all received frames  on 'MON'               |                             | dot11er.infra.tx_frame              |
| MON.rx_beacon     | Publish all beacons received on 'MON'                | dot11er.infra.rx_dispatcher |                                     |
| MON.rx_probe      | Publish all probe requests received on 'MON'         | dot11er.infra.rx_dispatcher |                                     |
| MON.rx_probe_resp | Publish all probe responses received on 'MON'        | dot11er.infra.rx_dispatcher |                                     |
| MON.rx_auth       | Publish all authentication frames received on 'MON'  | dot11er.infra.rx_dispatcher |                                     |
| MON.rx_assoc      | Publish all association requests received on 'MON'   | dot11er.infra.rx_dispatcher |                                     |
| MON.rx_assoc_resp | Publish all association responses received on 'MON'  | dot11er.infra.rx_dispatcher |                                     |
| MON.rx_eap_id     | Publish all EAP ID requests received on 'MON'        | dot11er.infra.rx_dispatcher |                                     |
| probe_request     | Send out probe requests                              |                             | dot11er.state_machine.probe_request |
