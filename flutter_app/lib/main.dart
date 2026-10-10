// DPI VPN ana ekrani — Baglan/Kopar + strateji secici + delay slider iskeleti.
import 'package:flutter/material.dart';
import 'dpi_bridge.dart';

void main() => runApp(const DpiVpnApp());

class DpiVpnApp extends StatelessWidget {
  const DpiVpnApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DPI VPN',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.teal),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  bool _connected = false; // local proxy acik/kapali (sunucu yok).
  DpiStrategyKind _kind = DpiStrategyKind.split; // Split veya Fragment.
  double _delayMs = 10; // SplitWithDelay icin slider (0-100 ms).
  String _status = 'hazir (local proxy kapali)';

  Future<void> _toggle() async {
    if (_connected) {
      await DpiBridge.disconnect();
      setState(() {
        _connected = false;
        _status = 'durdu (local proxy kapali)';
      });
    } else {
      final strat = _kind == DpiStrategyKind.split
          ? DpiStrategy.splitWithDelay(splitAt: 2, delayMs: _delayMs.round())
          : DpiStrategy.fragment(chunkSize: 512);
      await DpiBridge.connect(strat);
      setState(() {
        _connected = true;
        _status = 'calisiyor: local proxy + ${strat.describe()}';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('DPI VPN (local proxy)')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Mod: local proxy (uzak sunucu yok) — dpi-core v${DpiBridge.nativeVersion()}'),
            const SizedBox(height: 12),
            SegmentedButton<DpiStrategyKind>(
              segments: const [
                ButtonSegment(value: DpiStrategyKind.split, label: Text('Split')),
                ButtonSegment(value: DpiStrategyKind.fragment, label: Text('Fragment')),
              ],
              selected: {_kind},
              onSelectionChanged: (s) => setState(() => _kind = s.first),
            ),
            if (_kind == DpiStrategyKind.split) ...[
              const SizedBox(height: 8),
              Text('Gecikme: ${_delayMs.round()} ms'),
              Slider(
                value: _delayMs,
                min: 0,
                max: 100,
                divisions: 20,
                label: '${_delayMs.round()} ms',
                onChanged: (v) => setState(() => _delayMs = v),
              ),
            ],
            const SizedBox(height: 12),
            FilledButton(
              onPressed: _toggle,
              child: Text(_connected ? 'Kopar' : 'Baglan'),
            ),
            const SizedBox(height: 12),
            Text('Durum: $_status'),
          ],
        ),
      ),
    );
  }
}
