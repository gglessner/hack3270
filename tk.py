import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import tkinter.scrolledtext as tkk
import libhack3270
import sys, signal, platform, logging, datetime, re

class tkhack3270:
    def __init__(self, master, style, hack3270, logfile=None,loglevel=logging.WARNING):

        self.root = master  # Tk root
        self.style = style  # Tk Style
        self.hack3270 = hack3270 #Initialized hack3270 object
        self.last_db_id = 0

        # Create the Loggers (file and stderr)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        if logfile is not None:
            logger_formatter = logging.Formatter(
                '%(levelname)s :: {} :: %(funcName)s'
                ' :: %(message)s'.format(self.filename))
        else:
            logger_formatter = logging.Formatter(
                '%(module)s :: %(levelname)s :: %(funcName)s :: %(lineno)d :: %(message)s')
        # Log to stderr
        ch = logging.StreamHandler()
        ch.setFormatter(logger_formatter)
        ch.setLevel(loglevel)
        if not self.logger.hasHandlers():
            self.logger.addHandler(ch)

        self.style.theme_use("hackallthethings")
        self.tabControl = ttk.Notebook(self.root)

        self.tk_vars_init()

        self.root_height = 100
        self.exit_loop = False

        # handle ctrl-c
        self.logger.debug("Setting up SIGINT handler")
        signal.signal(signal.SIGINT, self.sigint_handler)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.frame = tk.Frame(self.root)
        self.frame.pack(side="top", expand=True, fill="both")

        self.root.title("{} v{}".format(libhack3270.__name__ ,libhack3270.__version__))

        self.darwin_resize()

        self.initial_window()

        if self.hack3270.is_offline():
            status = tk.Label(self.frame, text="OFFLINE LOG ANALYSIS MODE", bg='light grey').pack()
        else:
            self.hack3270.server_connect()


        if self.hack3270.is_offline():
            self.logger.debug("Offline mode enabled.")
            self.offline_init()
        else:
            self.hack3270.check_inject_3270e()

        self.tabs_init()

        if self.hack3270.is_offline():
            self.tabControl.tab(0, state="disabled")
            self.tabControl.tab(1, state="disabled")
            self.tabControl.tab(2, state="disabled")
            self.tabControl.tab(3, state="disabled")

        self.lastTab = 0
        self.tabNum = -1
        self.tabControl.bind("<<NotebookTabChanged>>", self.resize_window)

        self.root.after(10, self.run_it)
        self.root.mainloop()

    def run_it(self):

        if self.hack3270.is_offline():
            self.lastTab = self.tabNum
            self.root.update()
            return

        self.hack3270.daemon()
        if self.tabNum == 2: # Inject Keys
            self.aid_refresh()
        self.lastTab = self.tabNum
        self.root.update_idletasks()
        self.root.after(10, self.run_it)

    def tk_vars_init(self):
        self.logger.debug("Initializing Tk variables")
        self.tab1 = tk.Frame(self.tabControl, background="light grey")
        self.tab2 = tk.Frame(self.tabControl, background="light grey")
        self.tab3 = tk.Frame(self.tabControl, background="light grey")
        self.tab4 = tk.Frame(self.tabControl, background="light grey")
        self.tab5 = tk.Frame(self.tabControl, background="light grey")
        self.tab6 = tk.Frame(self.tabControl, background="light grey")
        self.tab7 = tk.Frame(self.tabControl, background="light grey")
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.hack_prot = tk.IntVar(value = 1)
        self.auto_server = tk.IntVar(value = 1)
        self.auto_client = tk.IntVar(value = 0)
        self.hack_sf = tk.IntVar(value = 1)
        self.hack_sfe = tk.IntVar(value = 1)
        self.hack_mf = tk.IntVar(value = 1)
        self.hack_hf = tk.IntVar(value = 1)
        self.hack_rnr = tk.IntVar(value = 1)
        self.hack_ei = tk.IntVar(value = 1)
        self.hack_hv = tk.IntVar(value = 1)
        self.hack_color_sfe = tk.IntVar(value = 1)
        self.hack_color_mf = tk.IntVar(value = 1)
        self.hack_color_sa = tk.IntVar(value = 1)
        self.hack_color_hv = tk.IntVar(value = 1)
        self.aid_no = tk.IntVar(value = 1)
        self.aid_qreply = tk.IntVar(value = 1)
        self.aid_enter = tk.IntVar(value = 0)
        self.aid_pf1 = tk.IntVar(value = 1)
        self.aid_pf2 = tk.IntVar(value = 1)
        self.aid_pf3 = tk.IntVar(value = 1)
        self.aid_pf4 = tk.IntVar(value = 1)
        self.aid_pf5 = tk.IntVar(value = 1)
        self.aid_pf6 = tk.IntVar(value = 1)
        self.aid_pf7 = tk.IntVar(value = 1)
        self.aid_pf8 = tk.IntVar(value = 1)
        self.aid_pf9 = tk.IntVar(value = 1)
        self.aid_pf10 = tk.IntVar(value = 1)
        self.aid_pf11 = tk.IntVar(value = 1)
        self.aid_pf12 = tk.IntVar(value = 1)
        self.aid_pf13 = tk.IntVar(value = 1)
        self.aid_pf14 = tk.IntVar(value = 1)
        self.aid_pf15 = tk.IntVar(value = 1)
        self.aid_pf16 = tk.IntVar(value = 1)
        self.aid_pf17 = tk.IntVar(value = 1)
        self.aid_pf18 = tk.IntVar(value = 1)
        self.aid_pf19 = tk.IntVar(value = 1)
        self.aid_pf20 = tk.IntVar(value = 1)
        self.aid_pf21 = tk.IntVar(value = 1)
        self.aid_pf22 = tk.IntVar(value = 1)
        self.aid_pf23 = tk.IntVar(value = 1)
        self.aid_pf24 = tk.IntVar(value = 1)
        self.aid_oicr = tk.IntVar(value = 1)
        self.aid_msr_mhs = tk.IntVar(value = 1)
        self.aid_select = tk.IntVar(value = 1)
        self.aid_pa1 = tk.IntVar(value = 1)
        self.aid_pa2 = tk.IntVar(value = 1)
        self.aid_pa3 = tk.IntVar(value = 1)
        self.aid_clear = tk.IntVar(value = 0)
        self.aid_sysreq = tk.IntVar(value = 1)
        self.inject_enter = tk.IntVar(value = 1)
        self.inject_clear = tk.IntVar(value = 0)
        self.inject_mask = tk.StringVar(value = '*')
        self.inject_key = tk.StringVar(value = 'ENTER')
        self.inject_trunc = tk.StringVar(value = 'SKIP')

    def tabs_init(self):
        # Tabs---
        self.logger.debug("Setting up Tabs")
        self.tabControl.add(self.tab1, text ='Hack Field Attributes')
        self.tabControl.add(self.tab2, text ='Hack Text Color')
        self.tabControl.add(self.tab3, text ='Inject Into Fields')
        self.tabControl.add(self.tab4, text ='Inject Key Presses')
        self.tabControl.add(self.tab5, text ='Logs')
        self.tabControl.add(self.tab6, text ='Statistics')
        self.tabControl.add(self.tab7, text ='Help')
        self.tabControl.pack(expand = 1, fill ="both")

        self.hack_field_tabs()
        self.hack_color_tabs()
        self.inject_fields_tab()
        self.inject_aids_tab()
        self.logs_tab()
        self.statistic_tab()
        self.help_tab()

    def hack_field_tabs(self):
        # Tab : Hack Field Attributes---
        self.logger.debug("Setting up Hack Field Attributes tab")
        self.a1 = tk.Label(self.tab1, text='Hack Fields:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=10)
        self.hack_button = ttk.Button(self.tab1, text='OFF', width=8, command=self.hack_button_pressed)
        self.hack_button.place(x=20,y=33)
        a2 = tk.Checkbutton(self.tab1, text='Disable Field Protection', bg='light grey', variable=self.hack_prot, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=150, y=0)
        a3 = tk.Checkbutton(self.tab1, text='Enable Hidden Fields', bg='light grey', variable=self.hack_hf, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=150, y=25)
        a4 = tk.Checkbutton(self.tab1, text='Remove Numeric Only Restrictions', bg='light grey', variable=self.hack_rnr, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=150, y=50)
        a6 = tk.Checkbutton(self.tab1, text='Start Field', bg='light grey', variable=self.hack_sf, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=420, y=2)
        a7 = tk.Checkbutton(self.tab1, text='Start Field Extended', bg='light grey', variable=self.hack_sfe, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=420, y=25)
        a9 = tk.Checkbutton(self.tab1, text='Modify Field', bg='light grey', variable=self.hack_mf, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=420, y=50)
        a10 = tk.Label(self.tab1, text='Hidden Field Highlighting:', font="TkDefaultFont 12 underline", bg='light grey').place(x=600, y=2)
        a11 = tk.Checkbutton(self.tab1, text='Enable Intensity', bg='light grey', variable=self.hack_ei, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=600, y=25)
        a12 = tk.Checkbutton(self.tab1, text='High Visibility', bg='light grey', variable=self.hack_hv, onvalue=1, offvalue=0, command=self.hack_toggle).place(x=600, y=50)

    def hack_color_tabs(self):
        # Tab : Hack Text Color
        self.logger.debug("Setting up Hack Text Color tab")
        d1 = tk.Label(self.tab2, text='Hack Color:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=10)
        self.hack_color_button = ttk.Button(self.tab2, text='OFF', width=8, command=self.hack_color_button_pressed)
        self.hack_color_button.place(x=20,y=33)
        d2 = tk.Checkbutton(self.tab2, text='Start Field Extended', bg='light grey', variable=self.hack_color_sfe, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=150, y=2)
        d3 = tk.Checkbutton(self.tab2, text='Modify Field', bg='light grey', variable=self.hack_color_mf, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=150, y=25)
        d4 = tk.Checkbutton(self.tab2, text='Set Attribute', bg='light grey', variable=self.hack_color_sa, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=150, y=50)
        d5 = tk.Label(self.tab2, text='Hidden Color Highlighting:', font="TkDefaultFont 12 underline", bg='light grey').place(x=330, y=2)
        d6 = tk.Checkbutton(self.tab2, text='High Visibility', bg='light grey', variable=self.hack_color_hv, onvalue=1, offvalue=0, command=self.hack_color_toggle).place(x=330, y=25)

    def inject_fields_tab(self):
        # Tab : Inject Into Fields---
        self.logger.debug("Setting up Inject Into Fields tab")
        b0 = tk.Label(self.tab3, text='Status:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=12)
        self.inject_status = tk.Label(self.tab3, text = 'Not Ready.', bg='light grey')
        self.inject_status.place(x=23, y=40)
        inject_file_button = ttk.Button(self.tab3, text='FILE', width=8, command=self.browse_files).place(x=125, y=2)
        inject_setup_button = ttk.Button(self.tab3, text='SETUP', width=8, command=self.inject_setup).place(x=200, y=2)
        inject_button = ttk.Button(self.tab3, text='INJECT', width=8, command=self.inject_go).place(x=275, y=2)
        inject_reset_button = ttk.Button(self.tab3, text='RESET', width=8, command=self.inject_reset).place(x=350, y=2)
        b1 = tk.Label(self.tab3, text='Mask:', font="TkDefaultFont 12 underline", bg='light grey').place(x=475, y=9)
        b2options = ["@", "#", "$", "%", "^", "&", "*"]
        b2 =ttk.OptionMenu(self.tab3, self.inject_mask, b2options[6], *b2options).place(x=525, y=8)
        b3 = tk.Label(self.tab3, text='Mode:', font="TkDefaultFont 12 underline", bg='light grey').place(x=600, y=9)
        b4options = ["SKIP", "TRUNC"]
        b4 =ttk.OptionMenu(self.tab3, self.inject_trunc, b4options[0], *b4options).place(x=650, y=8)
        b5 = tk.Label(self.tab3, text='Keys:', font="TkDefaultFont 12 underline", bg='light grey').place(x=750, y=9)
        b6options = ["ENTER", "ENTER+CLEAR", "ENTER+PF3", "ENTER+PF3+CLEAR"]
        b6 =ttk.OptionMenu(self.tab3, self.inject_key, b6options[0], *b6options).place(x=800, y=8)
    
    def inject_aids_tab(self):
        # Tab : Inject Key Presses---
        self.logger.debug("Setting up Inject Key Presses tab")
        send_button = ttk.Button(self.tab4, text = 'Send Keys', command=self.send_keys, width=10).place(x=25, y=12)
        self.send_label = tk.Label(self.tab4, text = 'Ready.', bg='light grey')
        self.send_label.place(x=25, y=50)
        c1 = tk.Checkbutton(self.tab4, text='NO',variable=self.aid_no, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=0)
        c2 = tk.Checkbutton(self.tab4, text='QREPLY',variable=self.aid_qreply, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=0)
        c3 = tk.Checkbutton(self.tab4, text='ENTER',variable=self.aid_enter, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=0)
        c4 = tk.Checkbutton(self.tab4, text='PF1',variable=self.aid_pf1, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=0)
        c5 = tk.Checkbutton(self.tab4, text='PF2',variable=self.aid_pf2, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=0)
        c6 = tk.Checkbutton(self.tab4, text='PF3',variable=self.aid_pf3, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=0)
        c7 = tk.Checkbutton(self.tab4, text='PF4',variable=self.aid_pf4, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=0)
        c8 = tk.Checkbutton(self.tab4, text='PF5',variable=self.aid_pf5, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=0)
        c9 = tk.Checkbutton(self.tab4, text='PF6',variable=self.aid_pf6, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=0)
        c10 = tk.Checkbutton(self.tab4, text='PF7',variable=self.aid_pf7, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=0)
        c11 = tk.Checkbutton(self.tab4, text='PF8',variable=self.aid_pf8, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=0)
        c12 = tk.Checkbutton(self.tab4, text='PF9',variable=self.aid_pf9, onvalue=1, offvalue=0, bg='light grey').place(x=1250, y=0)
        c13 = tk.Checkbutton(self.tab4, text='PF10',variable=self.aid_pf10, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=25)
        c14 = tk.Checkbutton(self.tab4, text='PF11',variable=self.aid_pf11, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=25)
        c15 = tk.Checkbutton(self.tab4, text='PF12',variable=self.aid_pf12, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=25)
        c16 = tk.Checkbutton(self.tab4, text='PF13',variable=self.aid_pf13, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=25)
        c17 = tk.Checkbutton(self.tab4, text='PF14',variable=self.aid_pf14, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=25)
        c18 = tk.Checkbutton(self.tab4, text='PF15',variable=self.aid_pf15, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=25)
        c19 = tk.Checkbutton(self.tab4, text='PF16',variable=self.aid_pf16, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=25)
        c20 = tk.Checkbutton(self.tab4, text='PF17',variable=self.aid_pf17, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=25)
        c21 = tk.Checkbutton(self.tab4, text='PF18',variable=self.aid_pf18, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=25)
        c22 = tk.Checkbutton(self.tab4, text='PF19',variable=self.aid_pf19, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=25)
        c23 = tk.Checkbutton(self.tab4, text='PF20',variable=self.aid_pf20, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=25)
        c24 = tk.Checkbutton(self.tab4, text='PF21',variable=self.aid_pf21, onvalue=1, offvalue=0, bg='light grey').place(x=1250, y=25)
        c25 = tk.Checkbutton(self.tab4, text='PF22',variable=self.aid_pf22, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=50)
        c26 = tk.Checkbutton(self.tab4, text='PF23',variable=self.aid_pf23, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=50)
        c27 = tk.Checkbutton(self.tab4, text='PF24',variable=self.aid_pf24, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=50)
        c28 = tk.Checkbutton(self.tab4, text='OICR',variable=self.aid_oicr, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=50)
        c29 = tk.Checkbutton(self.tab4, text='MSR_MHS',variable=self.aid_msr_mhs, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=50)
        c30 = tk.Checkbutton(self.tab4, text='SELECT',variable=self.aid_select, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=50)
        c31 = tk.Checkbutton(self.tab4, text='PA1',variable=self.aid_pa1, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=50)
        c32 = tk.Checkbutton(self.tab4, text='PA2',variable=self.aid_pa2, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=50)
        c33 = tk.Checkbutton(self.tab4, text='PA3',variable=self.aid_pa3, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=50)
        c34 = tk.Checkbutton(self.tab4, text='CLEAR',variable=self.aid_clear, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=50)
        c35 = tk.Checkbutton(self.tab4, text='SYSREQ',variable=self.aid_sysreq, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=50)

    def logs_tab(self):
        self.logger.debug("Setting up Logs tab")
        # Tab : Logs---
        self.treev = ttk.Treeview(self.tab5, selectmode="browse")
        self.treev.place(x=25, y=10, height=220, relwidth=0.985)
        verscrlbar = ttk.Scrollbar(self.tab5, orient ="vertical", command = self.treev.yview)
        self.treev.configure(yscrollcommand = verscrlbar.set)
        verscrlbar.place(x=5, y=10, height=220)
        self.treev["columns"] = ("1", "2", "3", "4", "5")
        self.treev['show'] = 'headings'
        self.treev.column("1", width = int(self.screen_width * 0.05), anchor ='center')
        self.treev.column("2", width = int(self.screen_width * 0.15), anchor ='center')
        self.treev.column("3", width = int(self.screen_width * 0.05), anchor ='center')
        self.treev.column("4", width = int(self.screen_width * 0.05), anchor ='center')
        self.treev.column("5", width = int(self.screen_width * 0.66), anchor ='sw')
        self.treev.heading("1", text ="ID", command=lambda:self.sort_numeric_column(self.treev, "1", False))
        self.treev.heading("2", text ="Timestamp", command=lambda:self.sort_column(self.treev, "2", False))
        self.treev.heading("3", text ="Sender", command=lambda:self.sort_column(self.treev, "3", False))
        self.treev.heading("4", text ="Length", command=lambda:self.sort_numeric_column(self.treev, "4", False))
        self.treev.heading("5", text ="Notes", command=lambda:self.sort_column(self.treev, "5", False))   

        self.update_logs_tab()

        self.treev.bind('<<TreeviewSelect>>', self.fetch_item)
        self.d1 = tkk.ScrolledText(master = self.tab5, wrap = tk.CHAR, height=12)
        if platform.system()=="Darwin":
        #    self.d1.place(x=25, y=235, width=screen_width - 105, height=220)
            self.d1.place(x=25, y=235, relwidth=0.985, height=220)
        else:
            self.d1.place(x=25, y=235, width=self.screen_width - 60, height=220)
        self.d1.config(state = "disabled")
        d2 = tk.Checkbutton(self.tab5, text='Auto Send Server', bg='light grey', variable=self.auto_server, onvalue=1, offvalue=0).place(x=25, y=465)
        d2 = tk.Checkbutton(self.tab5, text='Auto Send Client', bg='light grey', variable=self.auto_client, onvalue=1, offvalue=0).place(x=175, y=465)
        export_button = ttk.Button(self.tab5, text = 'Export to CSV', command=self.export_csv, width=10).place(x=345, y=465)
        self.export_label = tk.Label(self.tab5, text = 'Ready.', font="TkDefaultFont 12", bg='light grey')
        self.export_label.place(x=450, y=465)     

    def statistic_tab(self):
        self.logger.debug("Setting up Statistics tab")
        ip_label = tk.Label(self.tab6, text = 'Server IP Address: {}'.format(self.hack3270.get_ip_port()[0]),  font="TkDefaultFont 14", bg='light grey')
        ip_label.place(x=25, y=20)
        port_label = tk.Label(self.tab6, text = 'Server TCP Port: {}'.format(self.hack3270.get_ip_port()[1]), font="TkDefaultFont 14", bg='light grey')
        port_label.place(x=25, y=40)

        port_label = tk.Label(self.tab6, text = 'TLS Enabled: {}'.format(self.hack3270.get_tls()), font="TkDefaultFont 14", bg='light grey')
        port_label.place(x=25, y=60)
        
        total_connections = 0
        total_time = 0.0
        last_timestamp = 0.0
        start_timestamp = 0.0
        total_injections = 0
        total_hacks = 0
        server_messages = 0
        server_bytes = 0
        client_messages = 0
        client_bytes = 0


        for record in self.hack3270.all_logs():
            curr_timestamp = float(record[1])
            if record[2] == 'C':
                client_messages += 1
                client_bytes += record[4]
            else:
                server_messages += 1
                server_bytes += record[4]
            if record[2] == 'C' and "Send" in record[3]:
                total_injections += 1
            if record[2] == 'S' and "ENABLED" in record[3]:
                total_hacks += 1
            if record[2] == 'S' and record[4] == 3:
                total_connections += 1
                start_timestamp = curr_timestamp
                if last_timestamp > 0:
                    total_time += start_timestamp - last_timestamp
            else:
                last_timestamp = curr_timestamp
        total_time += start_timestamp - last_timestamp

        connections_label = tk.Label(self.tab6, text = 'Total Numer of TCP Connections: ' + str(total_connections), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=90)
        connections_label = tk.Label(self.tab6, text = 'Total Server Messages: ' + str(server_messages), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=110)
        connections_label = tk.Label(self.tab6, text = 'Total Client Messages: ' + str(client_messages), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=130)
        connections_label = tk.Label(self.tab6, text = 'Total Server Bytes: ' + str(server_bytes), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=150)
        connections_label = tk.Label(self.tab6, text = 'Total Client Bytes: ' + str(client_bytes), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=170)
        connections_label = tk.Label(self.tab6, text = 'Total Numer of Hacks: ' + str(total_hacks), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=190)
        connections_label = tk.Label(self.tab6, text = 'Total Numer of Injections: ' + str(total_injections), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=210)
        connections_label = tk.Label(self.tab6, text = 'Total Connect Time: ' + self.get_elapsed_time(total_time), font="TkDefaultFont 14", bg='light grey')
        connections_label.place(x=25, y=230)

    def help_tab(self):
        e1 = tkk.ScrolledText(master = self.tab7, wrap = tk.WORD, width = 20, height = 20)

        with open("README.MD", "r") as readme_file:
            e1.insert(tk.INSERT, readme_file.read())

        e1.pack(padx = 10, pady = 10, fill=tk.BOTH, expand=True)
        e1.config(state = "disabled")

    def update_logs_tab(self):
        for row in self.hack3270.all_logs(self.last_db_id):
            self.treev.insert('', 'end',text="",values=(row[0], datetime.datetime.fromtimestamp(float(row[1])), self.hack3270.expand_CS(row[2]), row[4], row[3]))
            self.last_db_id = int(row[0])

    def offline_init(self):
            my_record_num = 1
            while self.hack3270.check_record(my_record_num):
                if self.hack3270.check_server(my_record_num):
                    self.logger.debug("Playing server message: " + str(my_record_num))
                    self.hack3270.play_record(my_record_num)
                else:
                    self.logger.debug("Waiting for message from client.")
                    self.hack3270.recv()
                my_record_num = my_record_num + 1
            self.logger.debug("Telnet negotiation complete.")
            self.logger.debug("Displaying splash screen.")
            while self.hack3270.check_server(my_record_num):
                self.logger.debug("Playing server message: " + str(my_record_num))
                self.hack3270.play_record(my_record_num)
                my_record_num = my_record_num + 1

    def initial_window(self):
        ip, port = self.hack3270.get_proxy_ip_port()
        status = tk.Label(self.frame, text = "Waiting for TN3270 connection on  {}:{}".format(ip,port))
        status.pack()
        self.frame.update()
        self.hack3270.client_connect()
        status = tk.Label(self.frame, text = "Connection received.")
        status.pack()
        self.frame.update()

        self.logger.debug("Waiting for button press after inital connection")

        B = tk.Button(self.frame, text ="Click to Continue", command = self.continue_func)
        B.pack()
        while True:
            self.root.update()
            if self.exit_loop:
                break

    def continue_func(self):
        self.frame.destroy()
        self.root.update()
        self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
        self.exit_loop = True
        return

    def darwin_resize(self):
        if platform.system()=="Darwin":
            self.logger.debug("Darwin detected")
            self.root.geometry(str(int(self.screen_width / 2))+'x120+'+str(int((self.screen_width / 4)))+'+0')
        else:
            self.root.geometry(str(int(self.screen_width / 2))+'x100+'+str(int((self.screen_width / 4)))+'+0')
    
    def on_closing(self):

        self.root.protocol("WM_DELETE_WINDOW")
        self.hack3270.on_closing()
        self.tabControl.tab(0, state="disabled")
        self.tabControl.tab(1, state="disabled")
        self.tabControl.tab(3, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.root.destroy()
        self.logger.debug("Exiting.")
        sys.exit(0)

    def sigint_handler(self, signum, frame):
        self.logger.debug("Shutting Down")
        self.hack3270.on_closing()
        self.tabControl.tab(0, state="disabled")
        self.tabControl.tab(1, state="disabled")
        self.tabControl.tab(3, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.tabControl.tab(4, state="disabled")
        self.root.destroy()
        sys.exit(0)

    def hack_button_pressed(self):

        self.set_checkbox_values()
        if self.hack3270.get_hack_on():
            self.hack3270.set_hack_on(0)
            self.hack_button["text"] = 'OFF'
            self.root.update()
            self.hack3270.set_hack_toggled()
        else:
            self.hack3270.set_hack_on(1)
            self.hack_button["text"] = 'ON'
            self.root.update()
            self.hack3270.set_hack_toggled()
        return

    def hack_color_button_pressed(self):
        self.set_checkbox_values()

        if self.hack3270.get_hack_color_on():
            self.hack3270.set_hack_color_on(0)
            self.hack_color_button["text"] = 'OFF'
            self.root.update()
            self.hack3270.set_hack_color_toggled()
        else:
            self.hack3270.set_hack_color_on(1)
            self.hack_color_button["text"] = 'ON'
            self.root.update()
            self.hack3270.set_hack_color_toggled()
        return

    def hack_toggle(self):
        self.set_checkbox_values()
        self.hack3270.set_hack_toggled(1)
        return
    
    def hack_color_toggle(self):
        self.set_checkbox_values()
        self.hack3270.set_hack_color_toggled(1)
        return

    def set_checkbox_values(self):
        self.hack3270.set_hack_prot(self.hack_prot.get())
        self.hack3270.set_hack_hf(self.hack_hf.get())
        self.hack3270.set_hack_rnr(self.hack_rnr.get())
        self.hack3270.set_hack_sf(self.hack_sf.get())
        self.hack3270.set_hack_sfe(self.hack_sfe.get())
        self.hack3270.set_hack_mf(self.hack_mf.get())
        self.hack3270.set_hack_ei(self.hack_ei.get())
        self.hack3270.set_hack_hv(self.hack_hv.get())
        self.hack3270.set_hack_color_sfe(self.hack_color_sfe.get())
        self.hack3270.set_hack_color_mf(self.hack_color_mf.get())
        self.hack3270.set_hack_color_sa(self.hack_color_sa.get())
        self.hack3270.set_hack_color_hv(self.hack_color_hv.get())
        
    
    def browse_files(self):
        self.logger.debug("Opening browse file dialogue")
        self.inject_filename = filedialog.askopenfilename(initialdir = "injections", title = "Select file for injections", filetypes = (("Text Files", "*.txt"), ("All Files", "*")))
        if self.inject_filename:
            self.inject_status["text"] = "Filename set to: " + self.inject_filename
            self.logger.debug("Inject Filename: {}".format(self.inject_filename))
        else:
            self.inject_status["text"] = "Error: file not set."
            self.inject_filename = ""
        self.root.update()
        return
    
    def inject_setup(self):
        self.inject_status["text"] = "Submit data using mask character of '{}' to setup injection.".format(self.inject_mask.get())
        self.hack3270.set_inject_mask(self.inject_mask.get())
        self.root.update()
        self.hack3270.set_inject_setup_capture()
        return
    
    def inject_go(self):

        if (not self.inject_filename) and (not self.hack3270.get_inject_config_set()):
            self.inject_status["text"] = "First select a file for injection, then click SETUP."
            self.root.update()
            return
        
        if not self.inject_filename:
            self.logger.debug("Injection file not setup.")
            self.inject_status["text"] = "Injection file not set.  Click FILE."
            self.root.update()
            return
        
        if not self.hack3270.get_inject_config_set():
            self.logger.debug("Field for injection hasn't been setup.")
            self.inject_status["text"] = "Field for injection hasn't been setup.  Click SETUP."
            self.root.update()
            return

        self.logger.debug("All setup conditions met... injecting")
        self.disable_tabs(2)

        injections = open(self.inject_filename, 'r')
        while True:
            injection_line = injections.readline()

            if not injection_line:
                break

            injection_line = injection_line.rstrip()

            if self.inject_trunc.get() == 'TRUNC':
                injection_line = injection_line[:self.hack3270.get_inject_mask_len()]

            if len(injection_line) <= self.hack3270.get_inject_mask_len():
                injection_ebcdic = self.hack3270.get_ebcdic(injection_line)
                bytes_ebcdic = self.hack3270.get_inject_preamble() + injection_ebcdic + self.hack3270.get_inject_postamble()
                self.hack3270.write_log('C', 'Sending: ' + injection_line, bytes_ebcdic)
                self.hack3270.send_server(bytes_ebcdic)
                self.inject_status["text"] = "Sending: " + injection_line
                self.root.update()
                self.hack3270.tend_server()
            if self.inject_key.get() == 'ENTER+CLEAR':
                self.hack3270.send_key('CLEAR', b'\x6d')
            elif self.inject_key.get() == 'ENTER+PF3':
                self.hack3270.send_key('PF3', b'\xf3')
            elif self.inject_key.get() == 'ENTER+PF3+CLEAR':
                self.hack3270.send_key('PF3', b'\xf3')
                self.hack3270.send_key('CLEAR', b'\x6d')

        injections.close()
        self.enable_tabs()

        return

    def disable_tabs(self,skip=-1):
        '''
        disables all tabs except the skip (int) tab
        '''
        
        tabs = (num for num in range(0,7) if num != skip)
        for tab in tabs:
            self.logger.debug("Disabling Tab{}".format(tab))
            self.tabControl.tab(tab, state="disabled")

    def enable_tabs(self):
        for tab in range(0,7):
            self.logger.debug("Enabling Tab{}".format(tab))
            self.tabControl.tab(tab, state="normal")
            

    def inject_reset(self):
        self.hack3270.set_inject_config_set(0)
        self.inject_status["text"] = "Configuration cleared."
        self.root.update()
        return
    
    def send_keys(self):

        self.disable_tabs(3)


        # TODO: Rewrite this function to use a loop
        if self.aid_no.get(): self.hack3270.send_key('NO', b'\x60')
        if self.aid_qreply.get(): self.hack3270.send_key('QREPLY', b'\x61')
        if self.aid_enter.get(): self.hack3270.send_key('ENTER', b'\x7d')
        if self.aid_pf1.get(): self.hack3270.send_key('PF1', b'\xf1')
        if self.aid_pf2.get(): self.hack3270.send_key('PF2', b'\xf2')
        if self.aid_pf3.get(): self.hack3270.send_key('PF3', b'\xf3')
        if self.aid_pf4.get(): self.hack3270.send_key('PF4', b'\xf4')
        if self.aid_pf5.get(): self.hack3270.send_key('PF5', b'\xf5')
        if self.aid_pf6.get(): self.hack3270.send_key('PF6', b'\xf6')
        if self.aid_pf7.get(): self.hack3270.send_key('PF7', b'\xf7')
        if self.aid_pf8.get(): self.hack3270.send_key('PF8', b'\xf8')
        if self.aid_pf9.get(): self.hack3270.send_key('PF9', b'\xf9')
        if self.aid_pf10.get(): self.hack3270.send_key('PF10', b'\x7a')
        if self.aid_pf11.get(): self.hack3270.send_key('PF11', b'\x7b')
        if self.aid_pf12.get(): self.hack3270.send_key('PF12', b'\x7c')
        if self.aid_pf13.get(): self.hack3270.send_key('PF13', b'\xc1')
        if self.aid_pf14.get(): self.hack3270.send_key('PF14', b'\xc2')
        if self.aid_pf15.get(): self.hack3270.send_key('PF15', b'\xc3')
        if self.aid_pf16.get(): self.hack3270.send_key('PF16', b'\xc4')
        if self.aid_pf17.get(): self.hack3270.send_key('PF17', b'\xc5')
        if self.aid_pf18.get(): self.hack3270.send_key('PF18', b'\xc6')
        if self.aid_pf19.get(): self.hack3270.send_key('PF19', b'\xc7')
        if self.aid_pf20.get(): self.hack3270.send_key('PF20', b'\xc8')
        if self.aid_pf21.get(): self.hack3270.send_key('PF21', b'\xc9')
        if self.aid_pf22.get(): self.hack3270.send_key('PF22', b'\x4a')
        if self.aid_pf23.get(): self.hack3270.send_key('PF23', b'\x4b')
        if self.aid_pf24.get(): self.hack3270.send_key('PF24', b'\x4c')
        if self.aid_oicr.get(): self.hack3270.send_key('OICR', b'\xe6')
        if self.aid_msr_mhs.get(): self.hack3270.send_key('MSR_MHS', b'\xe7')
        if self.aid_select.get(): self.hack3270.send_key('SELECT', b'\x7e')
        if self.aid_pa1.get(): self.hack3270.send_key('PA1', b'\x6c')
        if self.aid_pa2.get(): self.hack3270.send_key('PA2', b'\x6e')
        if self.aid_pa3.get(): self.hack3270.send_key('PA3', b'\x6b')
        if self.aid_clear.get(): self.hack3270.send_key('CLEAR', b'\x6d')
        if self.aid_sysreq.get(): self.hack3270.send_key('SYSREQ', b'\xf0')
        self.send_label["text"] = 'Ready.'

        self.enable_tabs()
        return
    
    def sort_column(self, tree, col, reverse):
        data = [(tree.set(child, col), child) for child in tree.get_children('')]
        data.sort(reverse=reverse)
        for i, (_, child) in enumerate(data):
            tree.move(child, '', i)
        tree.heading(col, command=lambda:self.sort_column(tree, col, not reverse))

    def sort_numeric_column(self, tree, col, reverse):
        data = [(float(tree.set(child, col)), child) for child in tree.get_children('')]
        data.sort(reverse=reverse)
        for i, (_, child) in enumerate(data):
            tree.move(child, '', i)
        tree.heading(col, command=lambda:self.sort_numeric_column(tree, col, not reverse))

    def fetch_item(self,unused):

        style = ttk.Style()
        style.map('Treeview', foreground=[('focus', 'black')], background=[('focus', 'light blue')])
        current_item = self.treev.focus()
            
        dict_item = self.treev.item(current_item)
        record_id = dict_item['values'][0]
        record_cs = dict_item['values'][2]

        for row in self.hack3270.get_log(record_id):
            ebcdic_data = self.hack3270.get_ascii(row[5])
            self.d1.config(state='normal')
            self.d1.delete('1.0', tk.END)
            if re.search("^tn3270 ", row[3]):
                parsed_3270 = self.hack3270.parse_telnet(ebcdic_data)
            else:
                parsed_3270 = self.hack3270.parse_3270(ebcdic_data)
            self.d1.insert(tk.INSERT, parsed_3270)
            self.d1.config(state='disabled')
            self.root.update()
            if record_cs == "Server" and self.auto_server.get() == 1:
                self.hack3270.send_client(row[5])
            if record_cs == "Client" and self.auto_client.get() == 1:
                self.hack3270.send_server(row[5])
        return
    
    def export_csv(self):
        self.export_label["text"] = 'Starting export.'
        self.root.update()
        csv_filename = self.hack3270.export_csv()
        self.export_label["text"] = 'Export finished, filename is: ' + csv_filename
        self.root.update()
        return
    
    def get_elapsed_time(self, elapsed):
        if elapsed < 60:
            seconds = int(elapsed)
            return f"{seconds} seconds"
        elif elapsed < 3600:
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            return f"{minutes} minutes and {seconds} seconds"
        elif elapsed < 86400:
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{hours} hours, {minutes} minutes and {seconds} seconds"
        else:
            days = int(elapsed // 86400)
            hours = int((elapsed % 86400) // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            return f"{days} days, {hours} hours, {minutes} minutes and {seconds} seconds"
        
    def resize_window(self, event): 
        self.tabNum = self.tabControl.index(self.tabControl.select())
        self.logger.debug("Tab Changed to: {}".format(self.tabNum))
        if self.tabNum != self.lastTab:
            if self.tabNum == 0: # Hack Fields
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 1: # Hack Colors
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 2: # Inject
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 3: # Inject Key Presses
                self.aid_refresh()
                self.root.geometry(str(int(self.screen_width))+'x'+str(self.root_height)+'+0+0')
            if self.tabNum == 4: # Logs
                self.update_logs_tab()
                self.export_label["text"] = 'Ready.'
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 5: # Statistics
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
            if self.tabNum == 6: # Help
                self.root.geometry(str(int(self.screen_width))+'x525+0+0')
    
    def aid_refresh(self):
        aids = self.hack3270.current_aids()
        #self.logger.debug("Found aids: {}".format(aids))
        self.aid_setdef()
        if "PF1" in aids: self.aid_pf1.set(0)
        if "PF2" in aids: self.aid_pf2.set(0)
        if "PF3" in aids: self.aid_pf3.set(0)
        if "PF4" in aids: self.aid_pf4.set(0)
        if "PF5" in aids: self.aid_pf5.set(0)
        if "PF6" in aids: self.aid_pf6.set(0)
        if "PF7" in aids: self.aid_pf7.set(0)
        if "PF8" in aids: self.aid_pf8.set(0)
        if "PF9" in aids: self.aid_pf9.set(0)
        if "PF10" in aids: self.aid_pf10.set(0)
        if "PF11" in aids: self.aid_pf11.set(0)
        if "PF12" in aids: self.aid_pf12.set(0)
        if "PF13" in aids: self.aid_pf13.set(0)
        if "PF14" in aids: self.aid_pf14.set(0)
        if "PF15" in aids: self.aid_pf15.set(0)
        if "PF16" in aids: self.aid_pf16.set(0)
        if "PF17" in aids: self.aid_pf17.set(0)
        if "PF18" in aids: self.aid_pf18.set(0)
        if "PF19" in aids: self.aid_pf19.set(0)
        if "PF20" in aids: self.aid_pf20.set(0)
        if "PF21" in aids: self.aid_pf21.set(0)
        if "PF22" in aids: self.aid_pf22.set(0)
        if "PF23" in aids: self.aid_pf23.set(0)
        if "PF24" in aids: self.aid_pf24.set(0)
    
    def aid_setdef(self):
        #self.logger.debug("Resetting AID checkboxes")
        self.aid_no.set(1)
        self.aid_qreply.set(1)
        self.aid_enter.set(0)
        self.aid_pf1.set(1)
        self.aid_pf2.set(1)
        self.aid_pf3.set(1)
        self.aid_pf4.set(1)
        self.aid_pf5.set(1)
        self.aid_pf6.set(1)
        self.aid_pf7.set(1)
        self.aid_pf8.set(1)
        self.aid_pf9.set(1)
        self.aid_pf10.set(1)
        self.aid_pf11.set(1)
        self.aid_pf12.set(1)
        self.aid_pf13.set(1)
        self.aid_pf14.set(1)
        self.aid_pf15.set(1)
        self.aid_pf16.set(1)
        self.aid_pf17.set(1)
        self.aid_pf18.set(1)
        self.aid_pf19.set(1)
        self.aid_pf20.set(1)
        self.aid_pf21.set(1)
        self.aid_pf22.set(1)
        self.aid_pf23.set(1)
        self.aid_pf24.set(1)
        self.aid_oicr.set(1)
        self.aid_msr_mhs.set(1)
        self.aid_select.set(1)
        self.aid_pa1.set(1)
        self.aid_pa2.set(1)
        self.aid_pa3.set(1)
        self.aid_clear.set(0)
        self.aid_sysreq.set(1)
