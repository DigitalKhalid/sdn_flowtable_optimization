"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        Host1 = self.addHost( 'h1' )
        Host2 = self.addHost( 'h2' )
        Host3 = self.addHost( 'h3' )
        Host4 = self.addHost( 'h4' )
        Host5 = self.addHost( 'h5' )
        Host6 = self.addHost( 'h6' )
        Host7 = self.addHost( 'h7' )
        Host8 = self.addHost( 'h8' )
        Host9 = self.addHost( 'h9' )
        Host10 = self.addHost( 'h10' )
        Host11 = self.addHost( 'h11' )
        Host12 = self.addHost( 'h12' )
        Host13 = self.addHost( 'h13' )
        Host14 = self.addHost( 'h14' )
        Host15 = self.addHost( 'h15' )
        Host16 = self.addHost( 'h16' )
        Host17 = self.addHost( 'h17' )
        Host18 = self.addHost( 'h18' )
        Host19 = self.addHost( 'h19' )
        Host20 = self.addHost( 'h20' )
        Host21 = self.addHost( 'h21' )
        leftSwitch = self.addSwitch( 's1' )

        # Add links
        self.addLink( Host1, leftSwitch )
        self.addLink( Host2, leftSwitch )
        self.addLink( Host3, leftSwitch )
        self.addLink( Host4, leftSwitch )
        self.addLink( Host5, leftSwitch )
        self.addLink( Host6, leftSwitch )
        self.addLink( Host7, leftSwitch )
        self.addLink( Host8, leftSwitch )
        self.addLink( Host9, leftSwitch )
        self.addLink( Host10, leftSwitch )
        self.addLink( Host11, leftSwitch )
        self.addLink( Host12, leftSwitch )
        self.addLink( Host13, leftSwitch )
        self.addLink( Host14, leftSwitch )
        self.addLink( Host15, leftSwitch )
        self.addLink( Host16, leftSwitch )
        self.addLink( Host17, leftSwitch )
        self.addLink( Host18, leftSwitch )
        self.addLink( Host19, leftSwitch )
        self.addLink( Host20, leftSwitch )
        self.addLink( Host21, leftSwitch )


topos = { 'mytopo': ( lambda: MyTopo() ) }
