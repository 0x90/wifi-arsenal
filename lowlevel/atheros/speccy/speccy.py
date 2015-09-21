#!/usr/bin/python
from gi.repository import Gtk, Gdk
import spectrum_file
import signal
import sys
from math import ceil
import math
from scanner import Scanner


class Speccy(object):
    heatmap = {}
    max_per_freq = {}

    freq_min = 2402.0
    freq_max = 2472.0

    power_min = -110.0
    power_max = -20.0
    last_x = freq_max
    mpf_gen = 0
    mpf_gen_tbl = {}
    hmp_gen = 0
    hmp_gen_tbl = {}
    show_envelope = True
    show_heatmap = True
    lastframe = 0
    redraws = 0

    color_map = None
    sf = None

    def __init__(self, iface):
        self.color_map = self.gen_pallete()
        self.scanner = Scanner(iface)
        fn = '%s/spectral_scan0' % self.scanner.get_debugfs_dir()
        self.sf = spectrum_file.open(fn)

    def quit(self, *args):
        Gtk.main_quit()

    def cleanup(self, *args):
        self.scanner.stop()

    def on_key_press(self, w, event):
        key = Gdk.keyval_name(event.keyval)
        if key == 's':
            self.show_heatmap = not self.show_heatmap
        elif key == 'l':
            self.show_envelope = not self.show_envelope
        elif key == 'q':
            self.quit()

    def gen_pallete(self):
        # create a 256-color gradient from blue->green->white
        start_col = (0.1, 0.1, 1.0)
        mid_col = (0.1, 1.0, 0.1)
        end_col = (1.0, 1.0, 1.0)

        colors = [0] * 256
        for i in range(0, 256):
            if i < 128:
                sf = (128.0 - i) / 128.0
                sf2 = i / 128.0
                colors[i] = (start_col[0] * sf + mid_col[0] * sf2,
                            start_col[1] * sf + mid_col[1] * sf2,
                            start_col[2] * sf + mid_col[2] * sf2)
            else:
                sf = (256.0 - i) / 128.0
                sf2 = (i - 128.0) / 128.0
                colors[i] = (mid_col[0] * sf + end_col[0] * sf2,
                            mid_col[1] * sf + end_col[1] * sf2,
                            mid_col[2] * sf + end_col[2] * sf2)
        return colors

    def sample_to_viewport(self, freq, power, wx, wy):

        # normalize both frequency and power to [0,1] interval, and
        # then scale by window size
        freq_normalized = (freq - self.freq_min) / (self.freq_max - self.freq_min)
        freq_scaled = freq_normalized * wx

        power_normalized = (power - self.power_min) / (self.power_max - self.power_min)
        power_scaled = power_normalized * wy

        # flip origin to bottom left for y-axis
        power_scaled = wy - power_scaled

        return (freq_scaled, power_scaled)

    def draw_centered_text(self, cr, text, x, y):
        x_bearing, y_bearing, width, height = cr.text_extents(text)[:4]
        cr.move_to(x - width / 2 - x_bearing, y - height / 2 - y_bearing)
        cr.show_text(text)

    def draw_grid(self, cr, wx, wy):
        # clear the viewport with a black rectangle
        cr.rectangle(0, 0, wx, wy)
        cr.set_source_rgb(0, 0, 0)
        cr.fill()

        cr.set_source_rgb(1, 1, 1)
        cr.set_line_width(0.5)
        cr.set_dash([2.0, 2.0])
        for freq in range(int(self.freq_min), int(self.freq_max), 5):
            sx, sy = self.sample_to_viewport(freq, self.power_min, wx, wy)
            ex, ey = self.sample_to_viewport(freq, self.power_max, wx, wy)
            cr.move_to(sx, sy)
            cr.line_to(ex, ey)
            cr.stroke()

            if freq != self.freq_min and freq != self.freq_max:
                self.draw_centered_text(cr, "%d" % freq, ex, ey + 30)

        for power in range(int(self.power_min), int(self.power_max), 10):
            sx, sy = self.sample_to_viewport(self.freq_min, power, wx, wy)
            ex, ey = self.sample_to_viewport(self.freq_max, power, wx, wy)
            cr.move_to(sx, sy)
            cr.line_to(ex, ey)
            cr.stroke()

            if power != self.power_min and power != self.power_max:
                self.draw_centered_text(cr, "%d dBm" % power, sx + 30, ey)

        cr.set_dash([])

    def smooth_data(self, vals, window_len):
        smoothed = [self.power_min] * len(vals)
        half_window = window_len / 2
        for i in range(half_window, len(vals) - half_window):
            window = vals[i - half_window:i+half_window]
            smoothed[i] = sum(window) / float(len(window))
        return smoothed

    def update_data(self, w, frame_clock, user_data):

        time = frame_clock.get_frame_time()
        if time - self.lastframe > 1000:
            self.lastframe = time
        else:
            return True

        xydata = self.sf.read()
        if not xydata:
            return True

        hmp = self.heatmap
        mpf = self.max_per_freq

        for tsf, freq, noise, rssi, sdata in xydata:
            if freq < self.last_x:
                # we wrapped the scan...
                self.hmp_gen += 1
                self.mpf_gen += 1

            sumsq_sample = sum([x*x for x in sdata])
            for i, sample in enumerate(sdata):
                f = freq - (22.0 * 56 / 64.0) / 2 + (22.0 * (i + 0.5)/64.0)
                if sample == 0:
                    sample = 1
                if sumsq_sample == 0:
                    sumsq_sample = 1

                sigval = noise + rssi + \
                    20 * math.log10(sample) - 10 * math.log10(sumsq_sample)

                if f not in hmp or self.hmp_gen_tbl.get(f, 0) < self.hmp_gen:
                    hmp[f] = {}
                    self.hmp_gen_tbl[f] = self.hmp_gen

                arr = hmp[f]
                mody = ceil(sigval*2.0)/2.0
                arr.setdefault(mody, 0)
                arr[mody] += 1.0

                mpf.setdefault(f, 0)
                if sigval > mpf[f] or self.mpf_gen_tbl.get(f, 0) < self.mpf_gen:
                    mpf[f] = sigval
                    self.mpf_gen_tbl[f] = self.mpf_gen

            self.last_x = freq


        self.heatmap = hmp
        self.max_per_freq = mpf
        w.queue_draw()
        return True


    def draw(self, w, cr):

        wx, wy = (w.get_window().get_width(), w.get_window().get_height())
        self.draw_grid(cr, wx, wy)

        # samples
        rect_size = cr.device_to_user_distance(3, 3)

        zmax = 0
        for x in self.heatmap.keys():
            for y, value in self.heatmap[x].iteritems():
                if zmax < value:
                    zmax = self.heatmap[x][y]

        if not zmax:
            zmax = 1

        if self.show_heatmap:
            for x in self.heatmap.keys():
                for y, value in self.heatmap[x].iteritems():
                    # scale x to viewport
                    posx, posy = self.sample_to_viewport(x, y, wx, wy)

                    # don't bother drawing partially off-screen pixels
                    if posx < 0 or posx > wx or posy < 0 or posy > wy:
                        continue

                    color = self.color_map[int(len(self.color_map) * value / zmax) & 0xff]
                    cr.rectangle(posx-rect_size[0]/2, posy-rect_size[1]/2, rect_size[0], rect_size[1])
                    cr.set_source_rgba(color[0], color[1], color[2], .8)
                    cr.fill()

        if self.show_envelope:
            freqs = sorted(self.max_per_freq.keys())
            pow_data = [self.max_per_freq[f] for f in freqs]
            pow_data = self.smooth_data(pow_data, 4)

            x, y = self.sample_to_viewport(freqs[0], pow_data[0], wx, wy)
            cr.set_source_rgb(1, 1, 0)
            cr.move_to(x, y)
            for i, freq in enumerate(freqs[1:]):
                x, y = self.sample_to_viewport(freq, pow_data[i], wx, wy)
                cr.line_to(x, y)
            cr.stroke()


    def main(self):

        signal.signal(signal.SIGINT, self.quit)

        w = Gtk.Window()
        w.set_default_size(800, 400)
        a = Gtk.DrawingArea()
        w.add(a)

        a.add_tick_callback(self.update_data, None)

        w.connect('destroy', Gtk.main_quit)
        w.connect("key_press_event", self.on_key_press)
        a.connect('draw', self.draw)

        w.show_all()

        self.scanner.start()

        Gtk.main()

        self.cleanup()

if __name__ == '__main__':
    Speccy(sys.argv[1]).main()
