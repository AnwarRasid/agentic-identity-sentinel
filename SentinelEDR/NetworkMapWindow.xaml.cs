// ==========================================================================
//  Sentinel EDR — NetworkMapWindow.xaml.cs
//  Module 2: "The God's Eye View" — Visual Network Map
//  Target: .NET 8.0  |  WPF  |  System.Windows.Shapes
// ==========================================================================
//
//  ARCHITECTURE
//  ────────────
//  This window renders a force-directed-style network graph on a WPF
//  Canvas.  The local machine ("Localhost") is always pinned at the
//  centre.  Each IP detected by the AI pipeline is added as a satellite
//  node arranged in a circular layout around the centre.
//
//  Visual encoding:
//    • Node colour  → threat status (Red = malicious, Green = safe)
//    • Edge colour  → matches node colour for quick visual scanning
//    • Node size    → centre node is larger to anchor the viewer's eye
//    • Label        → IP address text placed beside each node
//
//  All drawing uses WPF's retained-mode graphics (Ellipse, Line,
//  TextBlock) — no GDI+, no third-party charting libraries.
//
// ==========================================================================

using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace SentinelEDR
{
    public partial class NetworkMapWindow : Window
    {
        // ==================================================================
        //  CONSTANTS — visual tuning knobs
        // ==================================================================

        /// <summary>Diameter of the centre (Localhost) node.</summary>
        private const double CENTER_NODE_SIZE = 40;

        /// <summary>Diameter of each satellite (IP) node.</summary>
        private const double SATELLITE_NODE_SIZE = 24;

        /// <summary>Radius of the orbit ring around the centre node.</summary>
        private const double ORBIT_RADIUS = 200;

        // ==================================================================
        //  COLOUR PALETTE — matches the main window's cyberpunk theme
        // ==================================================================

        private static readonly SolidColorBrush BrushBlue      = new(Color.FromRgb(0x44, 0x88, 0xFF));
        private static readonly SolidColorBrush BrushGreen     = new(Color.FromRgb(0x39, 0xFF, 0x14));
        private static readonly SolidColorBrush BrushRed       = new(Color.FromRgb(0xFF, 0x00, 0x3C));
        private static readonly SolidColorBrush BrushEdgeSafe  = new(Color.FromArgb(0x80, 0x39, 0xFF, 0x14));
        private static readonly SolidColorBrush BrushEdgeBad   = new(Color.FromArgb(0x80, 0xFF, 0x00, 0x3C));
        private static readonly SolidColorBrush BrushLabel     = new(Color.FromRgb(0x88, 0x92, 0xB0));
        private static readonly SolidColorBrush BrushBlueGlow  = new(Color.FromArgb(0x40, 0x44, 0x88, 0xFF));

        // ==================================================================
        //  FIELDS
        // ==================================================================

        /// <summary>Centre coordinates — recalculated on resize.</summary>
        private double _centerX;
        private double _centerY;

        /// <summary>Number of satellite nodes currently on the canvas.</summary>
        private int _nodeCount;

        /// <summary>
        /// Tracks IPs already on the map so we don't draw duplicates.
        /// Key = IP address, Value = the Ellipse shape on the canvas.
        /// </summary>
        private readonly Dictionary<string, Ellipse> _nodeMap = new();

        /// <summary>The centre Ellipse (Localhost) — kept for reference.</summary>
        private Ellipse? _centerNode;

        // ==================================================================
        //  CONSTRUCTOR
        // ==================================================================

        public NetworkMapWindow()
        {
            InitializeComponent();
        }

        // ==================================================================
        //  CANVAS SETUP — draws the centre node when the canvas is sized
        // ==================================================================

        /// <summary>
        /// Fired when the canvas receives its initial layout size (and on
        /// every subsequent resize).  We (re)draw the centre node here
        /// because Canvas.ActualWidth/Height are 0 during the constructor.
        /// </summary>
        private void MapCanvas_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            _centerX = MapCanvas.ActualWidth / 2;
            _centerY = MapCanvas.ActualHeight / 2;

            // Draw the Localhost centre node (once)
            if (_centerNode == null)
            {
                DrawCenterNode();
            }
            else
            {
                // Reposition the existing centre node on resize
                Canvas.SetLeft(_centerNode, _centerX - CENTER_NODE_SIZE / 2);
                Canvas.SetTop(_centerNode, _centerY - CENTER_NODE_SIZE / 2);
            }
        }

        /// <summary>
        /// Draws the static blue centre circle representing this machine.
        /// Includes a subtle glow ring and a "LOCALHOST" label.
        /// </summary>
        private void DrawCenterNode()
        {
            // Outer glow ring
            var glow = new Ellipse
            {
                Width  = CENTER_NODE_SIZE + 16,
                Height = CENTER_NODE_SIZE + 16,
                Fill   = BrushBlueGlow
            };
            Canvas.SetLeft(glow, _centerX - (CENTER_NODE_SIZE + 16) / 2);
            Canvas.SetTop(glow, _centerY - (CENTER_NODE_SIZE + 16) / 2);
            MapCanvas.Children.Add(glow);

            // Core node
            _centerNode = new Ellipse
            {
                Width           = CENTER_NODE_SIZE,
                Height          = CENTER_NODE_SIZE,
                Fill            = BrushBlue,
                StrokeThickness = 2,
                Stroke          = new SolidColorBrush(Color.FromRgb(0x66, 0xAA, 0xFF))
            };
            Canvas.SetLeft(_centerNode, _centerX - CENTER_NODE_SIZE / 2);
            Canvas.SetTop(_centerNode, _centerY - CENTER_NODE_SIZE / 2);
            MapCanvas.Children.Add(_centerNode);

            // Label below the centre node
            var label = new TextBlock
            {
                Text       = "LOCALHOST",
                Foreground = BrushBlue,
                FontSize   = 10,
                FontWeight = FontWeights.Bold,
                FontFamily = new FontFamily("Cascadia Code, Consolas, Courier New")
            };
            // Measure the text so we can centre it
            label.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            Canvas.SetLeft(label, _centerX - label.DesiredSize.Width / 2);
            Canvas.SetTop(label, _centerY + CENTER_NODE_SIZE / 2 + 4);
            MapCanvas.Children.Add(label);
        }

        // ==================================================================
        //  PUBLIC API — called by MainWindow to add IP nodes in real time
        // ==================================================================

        /// <summary>
        /// Spawns a new satellite node on the network map for the given IP.
        ///
        /// If the IP is already on the map, the call is ignored (no
        /// duplicates).  The node is positioned on a circular orbit
        /// around the centre, with evenly spaced angles.
        /// </summary>
        /// <param name="ip">The IP address to display.</param>
        /// <param name="isMalicious">
        ///   true  → Red node  (threat detected)
        ///   false → Green node (safe traffic)
        /// </param>
        public void AddNode(string ip, bool isMalicious)
        {
            // Prevent duplicate nodes for the same IP
            if (_nodeMap.ContainsKey(ip)) return;

            _nodeCount++;
            TxtNodeCount.Text = $"{_nodeCount} node{(_nodeCount == 1 ? "" : "s")}";

            // ── Calculate position on the orbit ring ─────────────────
            // Each node gets an angle based on its index.  We use a
            // golden-angle distribution for aesthetically pleasing
            // spacing that avoids overlap even with many nodes.
            double goldenAngle = Math.PI * (3.0 - Math.Sqrt(5.0));  // ~137.5°
            double angle = _nodeCount * goldenAngle;

            // Add slight radius variation so nodes don't land in a
            // perfect circle — feels more organic / force-directed
            double radiusJitter = ORBIT_RADIUS + Random.Shared.Next(-30, 30);
            double nodeX = _centerX + Math.Cos(angle) * radiusJitter;
            double nodeY = _centerY + Math.Sin(angle) * radiusJitter;

            // Clamp to canvas bounds with padding
            nodeX = Math.Clamp(nodeX, SATELLITE_NODE_SIZE, MapCanvas.ActualWidth - SATELLITE_NODE_SIZE);
            nodeY = Math.Clamp(nodeY, SATELLITE_NODE_SIZE, MapCanvas.ActualHeight - SATELLITE_NODE_SIZE);

            // ── Draw the connecting edge (line) first — behind node ──
            var edge = new Line
            {
                X1              = _centerX,
                Y1              = _centerY,
                X2              = nodeX,
                Y2              = nodeY,
                Stroke          = isMalicious ? BrushEdgeBad : BrushEdgeSafe,
                StrokeThickness = 1.5,
                StrokeDashArray = isMalicious ? new DoubleCollection { 4, 2 } : null
            };
            MapCanvas.Children.Add(edge);

            // ── Draw the satellite node ──────────────────────────────
            SolidColorBrush nodeFill = isMalicious ? BrushRed : BrushGreen;

            var node = new Ellipse
            {
                Width           = SATELLITE_NODE_SIZE,
                Height          = SATELLITE_NODE_SIZE,
                Fill            = nodeFill,
                StrokeThickness = 1.5,
                Stroke          = nodeFill,
                Opacity         = 0.9
            };
            Canvas.SetLeft(node, nodeX - SATELLITE_NODE_SIZE / 2);
            Canvas.SetTop(node, nodeY - SATELLITE_NODE_SIZE / 2);
            MapCanvas.Children.Add(node);

            // Track this node to prevent duplicates
            _nodeMap[ip] = node;

            // ── Draw the IP label next to the node ───────────────────
            var label = new TextBlock
            {
                Text       = ip,
                Foreground = BrushLabel,
                FontSize   = 9,
                FontFamily = new FontFamily("Cascadia Code, Consolas, Courier New")
            };

            // Position label to the right of the node, or left if
            // we're near the right edge of the canvas
            double labelX = nodeX + SATELLITE_NODE_SIZE / 2 + 6;
            if (labelX + 100 > MapCanvas.ActualWidth)
            {
                label.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                labelX = nodeX - SATELLITE_NODE_SIZE / 2 - label.DesiredSize.Width - 6;
            }

            Canvas.SetLeft(label, labelX);
            Canvas.SetTop(label, nodeY - 6);
            MapCanvas.Children.Add(label);
        }

        // ==================================================================
        //  PUBLIC API — reset the map (e.g., when user clears the feed)
        // ==================================================================

        /// <summary>
        /// Clears all satellite nodes and edges, keeping only the centre
        /// Localhost node.  Useful when the user resets the simulation.
        /// </summary>
        public void ClearMap()
        {
            MapCanvas.Children.Clear();
            _nodeMap.Clear();
            _nodeCount = 0;
            _centerNode = null;
            TxtNodeCount.Text = "0 nodes";

            // Redraw the centre node
            DrawCenterNode();
        }
    }
}
