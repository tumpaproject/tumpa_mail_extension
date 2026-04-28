// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation

enum MailExtensionRegistration {
    private static let extensionIdentifier = "in.kushaldas.tumpamail.extension"
    private static let extensionPoint = "com.apple.email.extension"
    private static let plugInKitURL = URL(fileURLWithPath: "/usr/bin/pluginkit")

    static func refresh() {
        DispatchQueue.global(qos: .utility).async {
            guard let currentExtensionURL = Bundle.main.builtInPlugInsURL?
                .appendingPathComponent("TumpaMailExtension.appex") else {
                return
            }

            let currentPath = currentExtensionURL.standardizedFileURL.path
            guard FileManager.default.fileExists(atPath: currentPath) else {
                return
            }

            let registeredPaths = registeredExtensionPaths()
            for path in registeredPaths where path != currentPath {
                _ = runPlugInKit(["-r", path])
            }

            _ = runPlugInKit(["-a", currentPath])
        }
    }

    private static func registeredExtensionPaths() -> Set<String> {
        let output = runPlugInKit([
            "-m", "-D",
            "-p", extensionPoint,
            "-i", extensionIdentifier
        ])

        return Set(output
            .split(separator: "\n")
            .compactMap { line -> String? in
                guard let pathStart = line.firstIndex(of: "/") else {
                    return nil
                }

                let path = String(line[pathStart...])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                guard path.hasSuffix(".appex") else {
                    return nil
                }

                return URL(fileURLWithPath: path).standardizedFileURL.path
            })
    }

    private static func runPlugInKit(_ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = plugInKitURL
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ""
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
