<?php /* Smarty version 2.6.26, created on 2010-08-26 16:34:57
         compiled from main.tpl */ ?>
<?php require_once(SMARTY_CORE_DIR . 'core.load_plugins.php');
smarty_core_load_plugins(array('plugins' => array(array('function', 'cycle', 'main.tpl', 31, false),array('modifier', 'date_format', 'main.tpl', 32, false),)), $this); ?>
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
<?php $_from = $this->_tpl_vars['result']; if (!is_array($_from) && !is_object($_from)) { settype($_from, 'array'); }if (count($_from)):
    foreach ($_from as $this->_tpl_vars['item']):
?>
<tr class="<?php echo smarty_function_cycle(array('values' => "odd, even"), $this);?>
">
<td class="clear"><?php echo ((is_array($_tmp=$this->_tpl_vars['item']['date'])) ? $this->_run_mod_handler('date_format', true, $_tmp, "%H:%M") : smarty_modifier_date_format($_tmp, "%H:%M")); ?>
</td>
<td class="image"><img src="/images/<?php echo $this->_tpl_vars['item']['os']; ?>
.png" border=0/></td>
<td><?php echo $this->_tpl_vars['item']['ip']; ?>
</td>
<td><b><?php echo $this->_tpl_vars['item']['desc']; ?>
</b></td>
<td><?php echo $this->_tpl_vars['item']['host']; ?>
</td>
<td><?php echo $this->_tpl_vars['item']['value']; ?>
</td>
</tr>
<?php endforeach; endif; unset($_from); ?>
</tbody>
</table>
</div>
</div>
<div id="bottom">
We already know about <?php echo $this->_tpl_vars['total_num']; ?>
 passwords on <?php echo $this->_tpl_vars['ips_count']; ?>
 ip addresses
<div class="copy">
CC2010 by <b>INVENT</b>
</div>
</div>
<script type="text/javascript" charset="utf-8" src="/js/mootools.js"></script>
<script type="text/javascript" charset="utf-8" src="/js/mootools-more.js"></script>
<script type="text/javascript">
<?php echo '
        window.addEvent(\'domready\',function() {
                var scroll = new Fx.Scroll(\'scroll-table\', {
                        wait: true,
                        duration: '; ?>
<?php echo $this->_tpl_vars['total_num']; ?>
<?php echo '000,
                        wheelStops: false,
                        transition: Fx.Transitions.linear
                });
                scroll.addEvent(\'complete\', function() {
                        setTimeout(function() {location.reload(true);}, 5000);
                });
                scroll.toBottom();
        });
'; ?>

</script>

</body>
</html>