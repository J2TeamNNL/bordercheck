// Draws Bordercheck.app's icon into an .iconset folder, for iconutil:
//
//	make-icon <out>.iconset
//
// The mark is the portal's (receiver/src/html.ts, FAVICON): a white shield
// with a check on a rounded tile with a blue → violet → teal gradient. The
// paths below are the SVG's, in its 24-unit space, placed as the favicon
// places them on its 64-unit tile; the tile itself sits on the macOS icon
// grid (824 of 1024 points, corner radius 185) so it lines up with other apps.
// Run by scripts/build-notifier.sh; nothing here reads a file.
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

/// M12 2.8 4.5 5.6v5.7c0 4.6 3.1 8.6 7.5 9.9 4.4-1.3 7.5-5.3 7.5-9.9V5.6L12 2.8Z
func shield() -> CGPath {
    let p = CGMutablePath()
    p.move(to: CGPoint(x: 12, y: 2.8))
    p.addLine(to: CGPoint(x: 4.5, y: 5.6))
    p.addLine(to: CGPoint(x: 4.5, y: 11.3))
    p.addCurve(to: CGPoint(x: 12, y: 21.2), control1: CGPoint(x: 4.5, y: 15.9), control2: CGPoint(x: 7.6, y: 19.9))
    p.addCurve(to: CGPoint(x: 19.5, y: 11.3), control1: CGPoint(x: 16.4, y: 19.9), control2: CGPoint(x: 19.5, y: 15.9))
    p.addLine(to: CGPoint(x: 19.5, y: 5.6))
    p.closeSubpath()
    return p
}

/// m8.6 12.1 2.4 2.4 4.5-4.7
func tick() -> CGPath {
    let p = CGMutablePath()
    p.move(to: CGPoint(x: 8.6, y: 12.1))
    p.addLine(to: CGPoint(x: 11.0, y: 14.5))
    p.addLine(to: CGPoint(x: 15.5, y: 9.8))
    return p
}

func draw(size px: Int) -> CGImage {
    let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let s = CGFloat(px) / 1024
    // SVG coordinates: y grows downwards.
    ctx.translateBy(x: 0, y: CGFloat(px))
    ctx.scaleBy(x: s, y: -s)

    let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
    let tilePath = CGPath(roundedRect: tile, cornerWidth: 185, cornerHeight: 185, transform: nil)
    // A soft drop shadow below the tile, as macOS icons have. Shadows are in
    // device pixels, untouched by the scale and flip above.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -10 * s), blur: 24 * s, color: rgb(0x000000, 0.30))
    ctx.addPath(tilePath)
    ctx.setFillColor(rgb(0x3a7bff))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(tilePath)
    ctx.clip()
    let gradient = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
                              colors: [rgb(0x3a7bff), rgb(0x7b4dff), rgb(0x1fc8b0)] as CFArray,
                              locations: [0, 0.55, 1])!
    ctx.drawLinearGradient(gradient, start: CGPoint(x: tile.minX, y: tile.minY),
                           end: CGPoint(x: tile.maxX, y: tile.maxY), options: [])
    // The favicon's inner highlight along the top edge.
    ctx.setStrokeColor(rgb(0xffffff, 0.35))
    ctx.setLineWidth(6)
    ctx.addPath(CGPath(roundedRect: tile.insetBy(dx: 3, dy: 3), cornerWidth: 182, cornerHeight: 182, transform: nil))
    ctx.strokePath()
    ctx.restoreGState()

    // The favicon draws the 24-unit mark at translate(13 13) scale(1.58) on a
    // 64-unit tile; here the tile is 824 points wide at (100, 100).
    let unit = 824.0 / 64.0
    ctx.saveGState()
    ctx.translateBy(x: 100 + 13 * unit, y: 100 + 13 * unit)
    ctx.scaleBy(x: 1.58 * unit, y: 1.58 * unit)
    ctx.setLineJoin(.round)
    ctx.setLineCap(.round)
    ctx.addPath(shield())
    ctx.setFillColor(rgb(0xffffff, 0.18))
    ctx.fillPath()
    ctx.addPath(shield())
    ctx.setStrokeColor(rgb(0xffffff))
    ctx.setLineWidth(1.6)
    ctx.strokePath()
    ctx.addPath(tick())
    ctx.setLineWidth(2)
    ctx.strokePath()
    ctx.restoreGState()
    return ctx.makeImage()!
}

func writePNG(_ img: CGImage, to url: URL) {
    guard let dst = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else {
        fatalError("cannot write \(url.path)")
    }
    CGImageDestinationAddImage(dst, img, nil)
    if !CGImageDestinationFinalize(dst) { fatalError("cannot write \(url.path)") }
}

guard CommandLine.arguments.count == 2, CommandLine.arguments[1].hasSuffix(".iconset") else {
    FileHandle.standardError.write(Data("usage: make-icon <out>.iconset\n".utf8))
    exit(2)
}
let out = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
// Up to 512 pixels (256 points at 2x). The 1024-pixel image alone was most of
// the app's size, and nothing shows this app's icon that large.
for pt in [16, 32, 128, 256] {
    writePNG(draw(size: pt), to: out.appendingPathComponent("icon_\(pt)x\(pt).png"))
    writePNG(draw(size: pt * 2), to: out.appendingPathComponent("icon_\(pt)x\(pt)@2x.png"))
}
