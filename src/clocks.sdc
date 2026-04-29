create_clock -name eth_refclk -period 20.0 -waveform {0 10.0} [get_ports {eth_refclk}]
