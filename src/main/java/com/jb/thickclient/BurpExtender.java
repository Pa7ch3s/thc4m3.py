package com.jb.thickclient;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;

/**
 * THC4M3 – Thick Client Bridge (MVP)
 * - Allow-list host/port/MIME to make your app’s traffic stand out.
 * - Label matching traffic in Proxy/HTTP history as [TCB].
 * - Generate a PAC file to proxy only your target hosts to Burp.
 *
 * NOTE: Burp can’t filter by OS process; we approximate via host/port rules.
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // UI
    private JPanel root;
    private JTextField hostAllow;
    private JTextField portAllow;
    private JTextField mimeAllow;
    private JCheckBox onlyMatches;
    private JTextArea notes;
    private JTable events;
    private DefaultTableModel eventsModel;

    // Filters
    private Pattern hostPattern = Pattern.compile(".*");
    private Set<Integer> allowedPorts = new HashSet<>(Arrays.asList(80, 443));
    private Pattern mimePattern = Pattern.compile(".*");

    private static final String TAG = "[TCB]";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("THC4M3 – Thick Client Bridge (MVP)");

        SwingUtilities.invokeLater(this::buildUi);
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);

        log("Loaded. Set allow-lists, then optionally generate a PAC file.");
    }

    private void buildUi() {
        root = new JPanel(new BorderLayout(12,12));
        root.setBorder(new EmptyBorder(10,10,10,10));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4,4,4,4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;

        hostAllow = new JTextField(".*(api|login|auth|gateway).*|localhost|127\\.0\\.0\\.1");
        portAllow = new JTextField("80,443,8080,8443");
        mimeAllow = new JTextField("^(application/json|application/xml|text/.*|application/octet-stream)$");
        onlyMatches = new JCheckBox("Show/annotate only matching traffic", false);

        JButton apply = new JButton(new AbstractAction("Apply Filters") {
            @Override public void actionPerformed(ActionEvent e) { applyFilters(); }
        });
        JButton genPac = new JButton(new AbstractAction("Generate PAC…") {
            @Override public void actionPerformed(ActionEvent e) { generatePac(); }
        });
        JButton help = new JButton(new AbstractAction("Quick Start") {
            @Override public void actionPerformed(ActionEvent e) { showQuickStart(); }
        });

        int row=0;
        c.gridx=0; c.gridy=row; top.add(new JLabel("Host allow (regex)"), c);
        c.gridx=1; c.gridy=row++; top.add(hostAllow, c);
        c.gridx=0; c.gridy=row; top.add(new JLabel("Port allow (comma)"), c);
        c.gridx=1; c.gridy=row++; top.add(portAllow, c);
        c.gridx=0; c.gridy=row; top.add(new JLabel("MIME allow (regex)"), c);
        c.gridx=1; c.gridy=row++; top.add(mimeAllow, c);
        c.gridx=0; c.gridy=row; top.add(onlyMatches, c);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(help); buttons.add(genPac); buttons.add(apply);
        c.gridx=1; c.gridy=row++; top.add(buttons, c);

        root.add(top, BorderLayout.NORTH);

        eventsModel = new DefaultTableModel(new Object[]{"Time","Direction","Host","Port","Method/Code","Label"}, 0);
        events = new JTable(eventsModel);
        root.add(new JScrollPane(events), BorderLayout.CENTER);

        notes = new JTextArea();
        notes.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        notes.setRows(6);
        notes.setBorder(BorderFactory.createTitledBorder("Notes / Outputs"));
        root.add(new JScrollPane(notes), BorderLayout.SOUTH);

        callbacks.addSuiteTab(this);
        applyFilters();
    }

    private void applyFilters() {
        try { hostPattern = Pattern.compile(hostAllow.getText()); }
        catch (Exception e) { warn("Bad host regex: " + e.getMessage()); }

        allowedPorts.clear();
        for (String p : portAllow.getText().split(",")) {
            try { allowedPorts.add(Integer.parseInt(p.trim())); } catch (Exception ignored) {}
        }

        try { mimePattern = Pattern.compile(mimeAllow.getText()); }
        catch (Exception e) { warn("Bad MIME regex: " + e.getMessage()); }

        log("Filters applied: host=" + hostPattern + ", ports=" + allowedPorts + ", mime=" + mimePattern);
    }

    private void showQuickStart() {
        String hint =
            "Quick Start — THC4M3 (MVP)\n\n" +
            "1) Point your thick client to Burp (127.0.0.1:8080) or set a PAC.\n" +
            "2) Add host patterns and ports above for your app.\n" +
            "3) Toggle ‘Show/annotate only matching traffic’ to reduce noise.\n" +
            "4) Exercise the app; matching traffic will be labeled [TCB].\n" +
            "Tip: For non-proxy-aware apps, use OS redirection (Proxifier/redsocks/pf).\n";
        notes.setText(hint);
    }

    private void generatePac() {
        try {
            String burpHost = InetAddress.getLocalHost().getHostAddress();
            int burpPort = 8080;

            IHttpRequestResponse[] hist = callbacks.getProxyHistory();
            if (hist != null && hist.length > 0) {
                try { burpPort = hist[0].getHttpService().getPort(); } catch (Throwable ignored) {}
            }

            String hostsRegex = hostAllow.getText();
            String pac = PacBuilder.buildSelectivePac(burpHost, burpPort, hostsRegex);
            File out = File.createTempFile("tcb-", ".pac");
            try (FileWriter fw = new FileWriter(out, StandardCharsets.UTF_8)) { fw.write(pac); }
            log("PAC written: " + out.getAbsolutePath());
            notes.append("\nSet system proxy using this PAC file for targeted interception.\n");
        } catch (IOException e) {
            warn("PAC generation failed: " + e.getMessage());
        }
    }

    private void log(String msg) {
        callbacks.printOutput(msg);
        eventsModel.addRow(new Object[]{timestamp(), "info", "-", "-", "-", msg});
    }
    private void warn(String msg) {
        callbacks.printError(msg);
        eventsModel.addRow(new Object[]{timestamp(), "warn", "-", "-", "-", msg});
    }
    private String timestamp() {
        return new SimpleDateFormat("HH:mm:ss").format(new Date());
    }

    // ITab
    @Override public String getTabCaption() { return "THC4M3"; }
    @Override public Component getUiComponent() { return root; }

    // IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            IHttpService svc = messageInfo.getHttpService();
            String host = svc.getHost();
            int port = svc.getPort();

            if (messageIsRequest) {
                if (matchesHostPort(host, port)) {
                    IRequestInfo ri = helpers.analyzeRequest(messageInfo);
                    List<String> headers = new ArrayList<>(ri.getHeaders());
                    headers.add("X-TCB: 1");
                    byte[] body = Arrays.copyOfRange(messageInfo.getRequest(), ri.getBodyOffset(), messageInfo.getRequest().length);
                    byte[] updated = helpers.buildHttpMessage(headers, body);
                    messageInfo.setRequest(updated);
                    messageInfo.setComment(TAG + " host/port match");
                    eventsModel.addRow(new Object[]{timestamp(), "→", host, String.valueOf(port), ri.getMethod(), "labeled"});
                }
            } else {
                if (matchesHostPort(host, port) && responseMimeAllowed(messageInfo)) {
                    IResponseInfo rr = helpers.analyzeResponse(messageInfo.getResponse());
                    messageInfo.setComment(TAG + " mime match: " + mimeFrom(rr));
                    eventsModel.addRow(new Object[]{timestamp(), "←", host, String.valueOf(port), String.valueOf(rr.getStatusCode()), "labeled"});
                }
            }
        } catch (Throwable t) {
            warn("processHttpMessage: " + t);
        }
    }

    // IProxyListener
    @Override public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) { /* noop */ }

    // Helpers
    private boolean matchesHostPort(String host, int port) {
        boolean hostOk = hostPattern.matcher(host).find();
        boolean portOk = allowedPorts.contains(port);
        return hostOk && portOk;
    }

    private boolean responseMimeAllowed(IHttpRequestResponse msg) {
        IResponseInfo rr = helpers.analyzeResponse(msg.getResponse());
        String mime = mimeFrom(rr);
        return mimePattern.matcher(mime).find();
    }

    private String mimeFrom(IResponseInfo rr) {
        String inferred = rr.getInferredMimeType();
        if (inferred == null || inferred.isEmpty() || "unknown".equalsIgnoreCase(inferred)) {
            inferred = rr.getStatedMimeType();
        }
        return inferred == null ? "unknown" : inferred;
    }

    // IMessageEditorController (placeholders)
    @Override public IHttpService getHttpService() { return null; }
    @Override public byte[] getRequest() { return new byte[0]; }
    @Override public byte[] getResponse() { return new byte[0]; }
}
