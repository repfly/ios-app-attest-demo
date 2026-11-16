import SwiftUI

struct ContentView: View {
    @State private var model = DemoViewModel()

    var body: some View {
        NavigationStack {
            List {
                if model.isSimulated {
                    Section {
                        Label {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Simulated mode — software key, not real App Attest").font(.subheadline.weight(.semibold))
                                if let message = model.simulatedModeOffMessage {
                                    Text(message).font(.caption).foregroundStyle(.red)
                                }
                            }
                        } icon: {
                            Image(systemName: "info.circle").foregroundStyle(.secondary)
                        }
                    }
                }

                if !model.isSupported {
                    Section {
                        Label {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("App Attest needs a physical device").font(.headline)
                                Text("DCAppAttestService.isSupported is false here (Simulator or no Secure Enclave). Run on an iPhone to register and send protected requests.")
                                    .font(.subheadline).foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                    }
                }

                Section("Server") {
                    TextField("http://<your-mac-ip>:8080", text: $model.serverURL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                }

                Section("Device") {
                    LabeledContent("App Attest supported") {
                        if model.isSimulated { Text("Simulated").foregroundStyle(.orange) } else { statusText(model.isSupported) }
                    }
                    LabeledContent("Key ID") {
                        Text(model.keyId.map { String($0.prefix(16)) + "…" } ?? "none")
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    LabeledContent("Attested by server") { statusText(model.isAttested) }
                }

                Section("Legitimate use") {
                    actionButton("Register device (attest)", systemImage: "checkmark.shield", enabled: model.canAttest) {
                        await model.register()
                    }
                    actionButton("Send protected transfer", systemImage: "arrow.right.circle", enabled: model.canTransfer) {
                        await model.transfer()
                    }
                }

                Section {
                    actionButton("Replay last request", systemImage: "arrow.clockwise",
                                 enabled: model.canTransfer && model.lastTransferBody != nil) { await model.replay() }
                    actionButton("Tamper: sign 10, send 10000", systemImage: "pencil.slash", enabled: model.canTransfer) {
                        await model.tamper()
                    }
                    actionButton("Stale / made-up challenge", systemImage: "clock.badge.xmark", enabled: model.canTransfer) {
                        await model.staleChallenge()
                    }
                    actionButton("Unknown key ID", systemImage: "key.slash", enabled: model.canTransfer) {
                        await model.unknownKey()
                    }
                } header: {
                    Text("Attacks")
                } footer: {
                    Text("Each attack should be rejected. Watch the server dashboard for the checklist.")
                }

                Section {
                    let canReset = !model.isBusy && model.keyId != nil
                    Button("Reset key", systemImage: "trash", role: .destructive) { model.resetKey() }
                        .opacity(canReset ? 1 : 0.35)
                        .disabled(!canReset)
                }

                Section {
                    if model.log.isEmpty {
                        Text("No actions yet.").foregroundStyle(.secondary)
                    }
                    ForEach(model.log) { entry in
                        LogEntryView(entry: entry)
                    }
                } header: {
                    HStack {
                        Text("Log")
                        Spacer()
                        if !model.log.isEmpty {
                            Button("Clear") { model.clearLog() }.font(.caption)
                        }
                    }
                }
            }
            .navigationTitle("App Attest Demo")
            .task(id: model.serverURL) {
                guard model.isSimulated else { return }
                try? await Task.sleep(for: .milliseconds(500)) // debounce typing
                await model.checkSimulatedServer()
            }
            .overlay(alignment: .top) {
                if model.isBusy { ProgressView().padding(8).background(.regularMaterial, in: Capsule()) }
            }
        }
    }

    private func statusText(_ value: Bool) -> some View {
        Text(value ? "Yes" : "No").foregroundStyle(value ? .green : .secondary)
    }

    private func actionButton(_ title: String, systemImage: String, enabled: Bool,
                              action: @escaping () async -> Void) -> some View {
        Button {
            Task { await action() }
        } label: {
            Label(title, systemImage: systemImage)
                // List rows don't always dim disabled buttons; make the state obvious.
                .opacity(enabled ? 1 : 0.35)
        }
        .disabled(!enabled)
    }
}

struct LogEntryView: View {
    let entry: LogEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(entry.title).font(.subheadline.weight(.semibold))
                Spacer()
                if let ok = entry.ok {
                    Text(ok ? "ACCEPTED" : "REJECTED")
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background((ok ? Color.green : Color.red).opacity(0.18), in: Capsule())
                        .foregroundStyle(ok ? .green : .red)
                } else if entry.error != nil {
                    Text("ERROR").font(.caption2.weight(.bold)).foregroundStyle(.orange)
                }
            }
            Text(entry.date, style: .time).font(.caption2).foregroundStyle(.secondary)
            if let expectation = entry.expectation {
                Text("Expected: \(expectation)").font(.caption).italic().foregroundStyle(.secondary)
            }
            ForEach(Array(entry.steps.enumerated()), id: \.offset) { index, step in
                Text("\(index + 1). \(step)").font(.caption).fixedSize(horizontal: false, vertical: true)
            }
            if !entry.checks.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(entry.checks) { check in
                        CheckRow(check: check)
                    }
                }
                .padding(.top, 2)
            }
        }
        .padding(.vertical, 4)
    }
}

struct CheckRow: View {
    let check: ServerCheck

    private var style: (icon: String, color: Color) {
        switch check.status {
        case "passed": return ("checkmark.circle.fill", .green)
        case "failed": return ("xmark.circle.fill", .red)
        default: return ("minus.circle", .gray)
        }
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: style.icon).foregroundStyle(style.color).font(.caption)
            VStack(alignment: .leading, spacing: 1) {
                Text(check.name).font(.caption.weight(.medium))
                    .foregroundStyle(check.status == "skipped" ? .secondary : .primary)
                Text(check.detail).font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

#Preview {
    ContentView()
}
