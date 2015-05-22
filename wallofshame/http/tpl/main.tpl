<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<head>
        <title>Wall of shame</title>

        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta http-equiv="Content-Language" content="en" />
        
        <meta name="author" content="INVENT" />

        <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="stylesheet" href="/css/main.css" type="text/css" media="screen" charset="utf-8" />
</head>
<body>
<div id="center">
<div id="wall">
<table cellpadding="0" cellspacing="0" id="wall_table">
<thead>
<tr>
<th class="clear"></th>
<th></th>
<th>IP Address</th>
<th>Type</th>
<th>Host</th>
<th>Captured data</th>
</tr>
</thead>
<tbody id="scroll-table">
{foreach from=$result item=item}
<tr class="{cycle values="odd, even"}">
<td class="clear">{$item.date|date_format:"%H:%M"}</td>
<td class="image"><img src="/images/{$item.os}.png" border=0/></td>
<td>{$item.ip}</td>
<td><b>{$item.desc}</b></td>
<td>{$item.host}</td>
<td>{$item.value}</td>
</tr>
{/foreach}
</tbody>
</table>
</div>
</div>
<div id="bottom">
We already know about {$total_num} passwords on {$ips_count} ip addresses
<div class="copy">
CC2010 by <b>INVENT</b>
</div>
</div>
<script type="text/javascript" charset="utf-8" src="/js/mootools.js"></script>
<script type="text/javascript" charset="utf-8" src="/js/mootools-more.js"></script>
<script type="text/javascript">
{literal}
        window.addEvent('domready',function() {
                var scroll = new Fx.Scroll('scroll-table', {
                        wait: true,
                        duration: {/literal}{$total_num}{literal}000,
                        wheelStops: false,
                        transition: Fx.Transitions.linear
                });
                scroll.addEvent('complete', function() {
                        setTimeout(function() {location.reload(true);}, 5000);
                });
                scroll.toBottom();
        });
{/literal}
</script>

</body>
</html>
