//! Shield Icon RGBA Generator for Raksha System Tray.
//! Produces 32x32 RGBA memory buffers for native tray icon rendering.

/// Generates a 32x32 pixel RGBA icon buffer (4,096 bytes) representing a shield.
/// When `active` is true, the shield interior is Emerald Green (#10B981).
/// When `active` is false, the shield interior is Crimson (#B43232).
/// Both feature a crisp white border (#FFFFFF) and transparent background.
pub fn generate_shield_icon_rgba(active: bool) -> Vec<u8> {
    const WIDTH: usize = 32;
    const HEIGHT: usize = 32;
    let mut buffer = vec![0u8; WIDTH * HEIGHT * 4];

    // Colors: RGBA format
    let fill_color = if active {
        [0x10, 0xB9, 0x81, 255] // Emerald Green (#10B981)
    } else {
        [0xB4, 0x32, 0x32, 255] // Crimson (#B43232)
    };
    let border_color = [255, 255, 255, 255]; // Pure White border

    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let idx = (y * WIDTH + x) * 4;
            let fx = x as f32;
            let fy = y as f32;

            // Shield geometry:
            // Height spans y = 4 to y = 27
            // Upper half (y: 4..16): consistent half-width of 10 pixels around center 15.5
            // Lower half (y: 16..27): tapers linearly down to the shield tip at (15.5, 27)
            if (4.0..=27.0).contains(&fy) {
                let max_half_w = 10.0;
                let half_w = if fy <= 16.0 {
                    max_half_w
                } else {
                    let progress = (fy - 16.0) / 11.0;
                    max_half_w * (1.0 - progress)
                };

                let center_x = 15.5;
                let dist_x = (fx - center_x).abs();

                if dist_x <= half_w {
                    // Border detection: outer 1.2 pixels or top/bottom edges
                    let is_border =
                        dist_x >= (half_w - 1.2) || fy <= 5.2 || (fy >= 25.8 && dist_x <= 1.5);
                    if is_border {
                        buffer[idx..idx + 4].copy_from_slice(&border_color);
                    } else {
                        buffer[idx..idx + 4].copy_from_slice(&fill_color);
                    }
                }
            }
        }
    }

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_dimensions() {
        let active = generate_shield_icon_rgba(true);
        assert_eq!(active.len(), 32 * 32 * 4);
        let inactive = generate_shield_icon_rgba(false);
        assert_eq!(inactive.len(), 32 * 32 * 4);
    }
}
