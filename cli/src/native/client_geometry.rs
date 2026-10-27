//! One native geometry authority for semantic rectangles and protected pixels.
//! CDP quads are already projected through same-renderer frame ancestors. Only
//! renderer-root (OOPIF) boundaries compose another transform. No DOM engine,
//! selector fallback, raw pixels, or wire-visible renderer identifiers live here.
use super::cdp::client::CdpClient;
use super::client_observation::{
    ObservationError, ObservationFrame, ObservationFramePolicy, SemanticFrameProof,
};
use super::client_session::{CancelSignal, OperationLease};
use super::element;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const MAX_FRAMES: usize = 256;
const MAX_POLYGON_POINTS: usize = 2048;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeometryError {
    InvalidGeometry,
    IncompleteInventory,
    StaleIdentity,
    Cancelled,
    Superseded,
    DeadlineExceeded,
    BackendFailure,
    CleanupFailed { primary: Option<Box<GeometryError>> },
}
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Polygon {
    pub points: Vec<Point>,
    enclosure: Option<[Interval; 2]>,
}
/// Semantic layout bounds may be a line or a point. This type cannot be used
/// as a masking polygon or an action hit region.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SemanticBounds(Bounds);
impl SemanticBounds {
    pub fn bounds(self) -> Bounds {
        self.0
    }
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PixelBounds {
    pub left: u32,
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
}
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Viewport {
    pub width: f64,
    pub height: f64,
    pub offset_x: f64,
    pub offset_y: f64,
    pub scale: f64,
    pub layout_width: f64,
    pub layout_height: f64,
}
// Directed rounding encloses every arithmetic operation used by renderer
// composition. Exact operations retain exact endpoints; no pixel epsilon is
// substituted for a proof near raster boundaries.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Interval {
    lo: f64,
    hi: f64,
}
impl Interval {
    const fn exact(x: f64) -> Self {
        Self { lo: x, hi: x }
    }
    fn add(self, b: Self) -> Self {
        fn directed(a: f64, b: f64, up: bool) -> f64 {
            let sum = a + b;
            let z = sum - a;
            let residual = (a - (sum - z)) + (b - z);
            if residual == 0. {
                sum
            } else if up {
                sum.next_up()
            } else {
                sum.next_down()
            }
        }
        Self {
            lo: directed(self.lo, b.lo, false),
            hi: directed(self.hi, b.hi, true),
        }
    }
    fn neg(self) -> Self {
        Self {
            lo: -self.hi,
            hi: -self.lo,
        }
    }
    fn sub(self, b: Self) -> Self {
        self.add(b.neg())
    }
    fn mul(self, b: Self) -> Self {
        let mut lo = f64::INFINITY;
        let mut hi = f64::NEG_INFINITY;
        for a in [self.lo, self.hi] {
            for b in [b.lo, b.hi] {
                let p = a * b;
                let exact = a == 0.
                    || b == 0.
                    || (p.abs() >= f64::MIN_POSITIVE / f64::EPSILON && a.mul_add(b, -p) == 0.);
                lo = lo.min(if exact { p } else { p.next_down() });
                hi = hi.max(if exact { p } else { p.next_up() });
            }
        }
        Self { lo, hi }
    }
    fn div(self, b: Self) -> Result<Self, GeometryError> {
        if b.lo <= 0. && b.hi >= 0. {
            return Err(GeometryError::InvalidGeometry);
        }
        let mut lo = f64::INFINITY;
        let mut hi = f64::NEG_INFINITY;
        for a in [self.lo, self.hi] {
            for b in [b.lo, b.hi] {
                let q = a / b;
                let exact = a == 0.
                    || (a.abs() >= f64::MIN_POSITIVE / f64::EPSILON
                        && q.is_finite()
                        && (-q).mul_add(b, a) == 0.);
                lo = lo.min(if exact { q } else { q.next_down() });
                hi = hi.max(if exact { q } else { q.next_up() });
            }
        }
        let value = Self { lo, hi };
        value.validate()?;
        Ok(value)
    }
    fn validate(self) -> Result<(), GeometryError> {
        if !self.lo.is_finite() || !self.hi.is_finite() || self.lo > self.hi {
            Err(GeometryError::InvalidGeometry)
        } else {
            Ok(())
        }
    }
    fn hull(self, b: Self) -> Self {
        Self {
            lo: self.lo.min(b.lo),
            hi: self.hi.max(b.hi),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq)]
struct Matrix([[f64; 3]; 3], [[Interval; 3]; 3]);
impl Matrix {
    const IDENTITY: Self = Self::exact([[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]]);
    const fn exact(m: [[f64; 3]; 3]) -> Self {
        Self(
            m,
            [
                [
                    Interval::exact(m[0][0]),
                    Interval::exact(m[0][1]),
                    Interval::exact(m[0][2]),
                ],
                [
                    Interval::exact(m[1][0]),
                    Interval::exact(m[1][1]),
                    Interval::exact(m[1][2]),
                ],
                [
                    Interval::exact(m[2][0]),
                    Interval::exact(m[2][1]),
                    Interval::exact(m[2][2]),
                ],
            ],
        )
    }
    fn enclose(self, p: Point) -> Result<[Interval; 2], GeometryError> {
        let p = [
            Interval::exact(p.x),
            Interval::exact(p.y),
            Interval::exact(1.),
        ];
        let mut sums = [Interval::exact(0.); 3];
        for (row, sum) in sums.iter_mut().enumerate() {
            for (k, p) in p.iter().enumerate() {
                *sum = sum.add(self.1[row][k].mul(*p));
            }
        }
        Ok([sums[0].div(sums[2])?, sums[1].div(sums[2])?])
    }
    fn apply(self, point: Point) -> Result<Point, GeometryError> {
        if !point.x.is_finite() || !point.y.is_finite() {
            return Err(GeometryError::InvalidGeometry);
        }
        let m = self.0;
        let denominator = m[2][0] * point.x + m[2][1] * point.y + m[2][2];
        // A projective horizon or numerically indeterminate denominator is not
        // masked with an arbitrary epsilon. Bound floating-point roundoff by
        // the standard gamma(n) model for this three-term dot product.
        let roundoff = gamma(5)
            * (m[2][0].abs() * point.x.abs() + m[2][1].abs() * point.y.abs() + m[2][2].abs());
        if denominator.abs() <= roundoff {
            return Err(GeometryError::InvalidGeometry);
        }
        let result = Point {
            x: (m[0][0] * point.x + m[0][1] * point.y + m[0][2]) / denominator,
            y: (m[1][0] * point.x + m[1][1] * point.y + m[1][2]) / denominator,
        };
        if !result.x.is_finite() || !result.y.is_finite() {
            return Err(GeometryError::InvalidGeometry);
        }
        Ok(result)
    }
    fn inverse(self) -> Result<Self, GeometryError> {
        let mut adj = [[0.; 3]; 3];
        let mut intervals = [[Interval::exact(0.); 3]; 3];
        for row in 0..3 {
            for col in 0..3 {
                let rs = [(col + 1) % 3, (col + 2) % 3];
                let cs = [(row + 1) % 3, (row + 2) % 3];
                adj[row][col] = self.0[rs[0]][cs[0]] * self.0[rs[1]][cs[1]]
                    - self.0[rs[0]][cs[1]] * self.0[rs[1]][cs[0]];
                intervals[row][col] = self.1[rs[0]][cs[0]]
                    .mul(self.1[rs[1]][cs[1]])
                    .sub(self.1[rs[0]][cs[1]].mul(self.1[rs[1]][cs[0]]));
            }
        }
        let determinant = (0..3).map(|k| self.0[0][k] * adj[k][0]).sum::<f64>();
        let mut bounded = Interval::exact(0.);
        for (k, row) in intervals.iter().enumerate() {
            bounded = bounded.add(self.1[0][k].mul(row[0]));
        }
        // The interval must exclude zero: an ill-conditioned inverse cannot
        // become input authority merely because its nominal determinant exists.
        for row in 0..3 {
            for col in 0..3 {
                intervals[row][col] = intervals[row][col].div(bounded)?;
                adj[row][col] /= determinant;
                if !adj[row][col].is_finite() {
                    return Err(GeometryError::InvalidGeometry);
                }
            }
        }
        Ok(Self(adj, intervals))
    }
    fn then(self, outer: Self) -> Result<Self, GeometryError> {
        let mut m = [[0.; 3]; 3];
        for (row, values) in m.iter_mut().enumerate() {
            for (column, value) in values.iter_mut().enumerate() {
                *value = (0..3).map(|k| outer.0[row][k] * self.0[k][column]).sum();
                if !value.is_finite() {
                    return Err(GeometryError::InvalidGeometry);
                }
            }
        }
        let mut ranges = [[Interval::exact(0.); 3]; 3];
        for (row, values) in ranges.iter_mut().enumerate() {
            for (column, value) in values.iter_mut().enumerate() {
                for k in 0..3 {
                    *value = value.add(outer.1[row][k].mul(self.1[k][column]));
                }
                value.validate()?;
            }
        }
        Ok(Self(m, ranges))
    }
    fn rectangle_to_quad(source: Bounds, quad: &[Point; 4]) -> Result<Self, GeometryError> {
        source.validate()?;
        validate_convex(quad)?;
        let [p0, p1, p2, p3] = *quad;
        let dx1 = p1.x - p2.x;
        let dx2 = p3.x - p2.x;
        let dx3 = p0.x - p1.x + p2.x - p3.x;
        let dy1 = p1.y - p2.y;
        let dy2 = p3.y - p2.y;
        let dy3 = p0.y - p1.y + p2.y - p3.y;
        let (g, h) = if dx3 == 0. && dy3 == 0. {
            (0., 0.)
        } else {
            let determinant = dx1 * dy2 - dx2 * dy1;
            if determinant.abs() <= gamma(3) * (dx1.abs() * dy2.abs() + dx2.abs() * dy1.abs()) {
                return Err(GeometryError::InvalidGeometry);
            }
            (
                (dx3 * dy2 - dx2 * dy3) / determinant,
                (dx1 * dy3 - dx3 * dy1) / determinant,
            )
        };
        let mut unit = Self::exact([
            [p1.x - p0.x + g * p1.x, p3.x - p0.x + h * p3.x, p0.x],
            [p1.y - p0.y + g * p1.y, p3.y - p0.y + h * p3.y, p0.y],
            [g, h, 1.],
        ]);
        if [1., 1. + g, 1. + h, 1. + g + h]
            .iter()
            .any(|v| !v.is_finite() || *v <= 0.)
        {
            return Err(GeometryError::InvalidGeometry);
        }
        let mut normalize = Self::exact([
            [1. / source.width, 0., -source.x / source.width],
            [0., 1. / source.height, -source.y / source.height],
            [0., 0., 1.],
        ]);
        let x = quad.map(|p| Interval::exact(p.x));
        let y = quad.map(|p| Interval::exact(p.y));
        let ix1 = x[1].sub(x[2]);
        let ix2 = x[3].sub(x[2]);
        let ix3 = x[0].sub(x[1]).add(x[2]).sub(x[3]);
        let iy1 = y[1].sub(y[2]);
        let iy2 = y[3].sub(y[2]);
        let iy3 = y[0].sub(y[1]).add(y[2]).sub(y[3]);
        let (ig, ih) =
            if dx3 == 0. && dy3 == 0. && ix3 == Interval::exact(0.) && iy3 == Interval::exact(0.) {
                (Interval::exact(0.), Interval::exact(0.))
            } else {
                let det = ix1.mul(iy2).sub(ix2.mul(iy1));
                (
                    ix3.mul(iy2).sub(ix2.mul(iy3)).div(det)?,
                    ix1.mul(iy3).sub(ix3.mul(iy1)).div(det)?,
                )
            };
        unit.1 = [
            [
                x[1].sub(x[0]).add(ig.mul(x[1])),
                x[3].sub(x[0]).add(ih.mul(x[3])),
                x[0],
            ],
            [
                y[1].sub(y[0]).add(ig.mul(y[1])),
                y[3].sub(y[0]).add(ih.mul(y[3])),
                y[0],
            ],
            [ig, ih, Interval::exact(1.)],
        ];
        normalize.1[0][0] = Interval::exact(1.).div(Interval::exact(source.width))?;
        normalize.1[1][1] = Interval::exact(1.).div(Interval::exact(source.height))?;
        normalize.1[0][2] = Interval::exact(-source.x).div(Interval::exact(source.width))?;
        normalize.1[1][2] = Interval::exact(-source.y).div(Interval::exact(source.height))?;
        let matrix = normalize.then(unit)?;
        for (source, expected) in source.corners().iter().zip(quad) {
            let actual = matrix.apply(*source)?;
            let bound = gamma(64)
                * (1. + expected.x.abs() + expected.y.abs() + source.x.abs() + source.y.abs());
            if (actual.x - expected.x).abs() > bound || (actual.y - expected.y).abs() > bound {
                return Err(GeometryError::InvalidGeometry);
            }
        }
        Ok(matrix)
    }
}
fn gamma(operations: u32) -> f64 {
    let error = f64::EPSILON / 2. * f64::from(operations);
    error / (1. - error)
}
fn cross(a: Point, b: Point, c: Point) -> f64 {
    (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x)
}
fn validate_convex(quad: &[Point; 4]) -> Result<(), GeometryError> {
    if quad.iter().any(|p| !p.x.is_finite() || !p.y.is_finite()) {
        return Err(GeometryError::InvalidGeometry);
    }
    let signs = (0..4)
        .map(|i| cross(quad[i], quad[(i + 1) % 4], quad[(i + 2) % 4]))
        .collect::<Vec<_>>();
    if signs.iter().any(|s| !s.is_finite() || *s == 0.)
        || signs.iter().any(|s| s.signum() != signs[0].signum())
    {
        return Err(GeometryError::InvalidGeometry);
    }
    Ok(())
}
impl Bounds {
    fn validate(self) -> Result<(), GeometryError> {
        if [self.x, self.y, self.width, self.height]
            .iter()
            .any(|v| !v.is_finite())
            || self.width <= 0.
            || self.height <= 0.
        {
            return Err(GeometryError::InvalidGeometry);
        }
        Ok(())
    }
    fn corners(self) -> [Point; 4] {
        [
            Point {
                x: self.x,
                y: self.y,
            },
            Point {
                x: self.x + self.width,
                y: self.y,
            },
            Point {
                x: self.x + self.width,
                y: self.y + self.height,
            },
            Point {
                x: self.x,
                y: self.y + self.height,
            },
        ]
    }
}
impl Polygon {
    /// Test fixture only; production polygons must come from a verified snapshot.
    #[cfg(test)]
    pub(crate) fn rectangle_for_test(x: f64, y: f64, width: f64, height: f64) -> Self {
        assert!([x, y, width, height].iter().all(|value| value.is_finite()));
        assert!(width >= 0. && height >= 0.);
        Self {
            points: Bounds {
                x,
                y,
                width,
                height,
            }
            .corners()
            .to_vec(),
            enclosure: None,
        }
    }
    pub fn bounds(&self) -> Option<Bounds> {
        let first = self.points.first()?;
        let (mut left, mut right, mut top, mut bottom) = (first.x, first.x, first.y, first.y);
        for p in &self.points {
            left = left.min(p.x);
            right = right.max(p.x);
            top = top.min(p.y);
            bottom = bottom.max(p.y);
        }
        Some(Bounds {
            x: left,
            y: top,
            width: right - left,
            height: bottom - top,
        })
    }
    fn transform(&self, matrix: Matrix) -> Result<Self, GeometryError> {
        // Finite corner coordinates alone do not prove a finite polygon: a
        // projective horizon can cross an edge between two finite endpoints.
        let mut denominators = None::<Interval>;
        for point in &self.points {
            let w = matrix.1[2][0]
                .mul(Interval::exact(point.x))
                .add(matrix.1[2][1].mul(Interval::exact(point.y)))
                .add(matrix.1[2][2]);
            w.validate()?;
            denominators = Some(denominators.map_or(w, |old| old.hull(w)));
        }
        if denominators.is_some_and(|w| w.lo <= 0. && w.hi >= 0.) {
            return Err(GeometryError::InvalidGeometry);
        }
        let mut enclosure = None::<[Interval; 2]>;
        for point in &self.points {
            let bounds = matrix.enclose(*point)?;
            enclosure = Some(match enclosure {
                None => bounds,
                Some(old) => [old[0].hull(bounds[0]), old[1].hull(bounds[1])],
            });
        }
        Ok(Self {
            enclosure,
            points: self
                .points
                .iter()
                .map(|p| matrix.apply(*p))
                .collect::<Result<_, _>>()?,
        })
    }
    fn clip(&self, quad: &[Point; 4]) -> Result<Self, GeometryError> {
        validate_convex(quad)?;
        let orientation = cross(quad[0], quad[1], quad[2]).signum();
        let mut points = self.points.clone();
        for index in 0..4 {
            if points.is_empty() {
                break;
            }
            let a = quad[index];
            let b = quad[(index + 1) % 4];
            let input = std::mem::take(&mut points);
            let mut previous = *input.last().ok_or(GeometryError::InvalidGeometry)?;
            let mut previous_side = orientation * cross(a, b, previous);
            for current in input {
                let side = orientation * cross(a, b, current);
                if !side.is_finite() || !previous_side.is_finite() {
                    return Err(GeometryError::InvalidGeometry);
                }
                if (side >= 0.) != (previous_side >= 0.) {
                    let divisor = previous_side - side;
                    if divisor == 0. || !divisor.is_finite() {
                        return Err(GeometryError::InvalidGeometry);
                    }
                    let t = previous_side / divisor;
                    points.push(Point {
                        x: previous.x + t * (current.x - previous.x),
                        y: previous.y + t * (current.y - previous.y),
                    });
                }
                if side >= 0. {
                    points.push(current);
                }
                previous = current;
                previous_side = side;
            }
            if points.len() > MAX_POLYGON_POINTS {
                return Err(GeometryError::InvalidGeometry);
            }
        }
        // The exact clipped polygon is contained by both the original interval
        // envelope and the native clip's axis envelope. Keep this conservative
        // enclosure instead of pretending rounded intersection vertices exact.
        let clip_x = quad.iter().map(|p| p.x).fold(
            Interval {
                lo: f64::INFINITY,
                hi: f64::NEG_INFINITY,
            },
            |a, x| a.hull(Interval::exact(x)),
        );
        let clip_y = quad.iter().map(|p| p.y).fold(
            Interval {
                lo: f64::INFINITY,
                hi: f64::NEG_INFINITY,
            },
            |a, y| a.hull(Interval::exact(y)),
        );
        let enclosure = self.enclosure.map(|old| {
            [
                Interval {
                    lo: old[0].lo.max(clip_x.lo),
                    hi: old[0].hi.min(clip_x.hi),
                },
                Interval {
                    lo: old[1].lo.max(clip_y.lo),
                    hi: old[1].hi.min(clip_y.hi),
                },
            ]
        });
        Ok(Self { points, enclosure })
    }
    fn clip_proven(&self, clip: &Polygon) -> Result<Self, GeometryError> {
        let quad: [Point; 4] = clip
            .points
            .clone()
            .try_into()
            .map_err(|_| GeometryError::InvalidGeometry)?;
        let mut result = self.clip(&quad)?;
        if let (Some(original), Some(boundary)) = (self.enclosure, clip.enclosure) {
            result.enclosure = Some([
                Interval {
                    lo: original[0].lo.max(boundary[0].lo),
                    hi: original[0].hi.min(boundary[0].hi),
                },
                Interval {
                    lo: original[1].lo.max(boundary[1].lo),
                    hi: original[1].hi.min(boundary[1].hi),
                },
            ]);
        }
        Ok(result)
    }
    /// Outward integer coverage uses the actual returned bitmap dimensions,
    /// not guessed DPR. Integer floor/ceil preserve fractional outward coverage.
    pub fn raster_bounds(
        &self,
        viewport: Viewport,
        width: u32,
        height: u32,
    ) -> Result<Option<PixelBounds>, GeometryError> {
        if width == 0 || height == 0 || viewport.width <= 0. || viewport.height <= 0. {
            return Err(GeometryError::InvalidGeometry);
        }
        let bounds = match self.bounds() {
            Some(bounds) => bounds,
            None => {
                if let Some([x, y]) = self.enclosure {
                    Bounds {
                        x: x.lo,
                        y: y.lo,
                        width: x.hi - x.lo,
                        height: y.hi - y.lo,
                    }
                } else {
                    return Ok(None);
                }
            }
        };
        if self
            .enclosure
            .is_some_and(|[x, y]| x.lo >= x.hi || y.lo >= y.hi)
        {
            return Ok(None);
        }

        let enclosure = self.enclosure.unwrap_or([
            Interval {
                lo: bounds.x,
                hi: bounds.x + bounds.width,
            },
            Interval {
                lo: bounds.y,
                hi: bounds.y + bounds.height,
            },
        ]);
        let x = enclosure[0]
            .mul(Interval::exact(f64::from(width)))
            .div(Interval::exact(viewport.width))?;
        let y = enclosure[1]
            .mul(Interval::exact(f64::from(height)))
            .div(Interval::exact(viewport.height))?;
        Ok(Some(PixelBounds {
            left: x.lo.floor().clamp(0., f64::from(width)) as u32,
            top: y.lo.floor().clamp(0., f64::from(height)) as u32,
            right: x.hi.ceil().clamp(0., f64::from(width)) as u32,
            bottom: y.hi.ceil().clamp(0., f64::from(height)) as u32,
        }))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SessionProof {
    root: String,
    // Excluded renderer roots retain identity, never fabricated geometry.
    viewport: Option<Viewport>,
}
#[derive(Debug, Clone, PartialEq)]
struct FrameProof {
    id: String,
    loader: String,
    session: String,
    parent: Option<String>,
    owner: Option<i64>,
    owner_quad: Option<[Point; 4]>,
    owner_size: Option<(f64, f64)>,
}
#[derive(Debug, Clone)]
pub struct GeometrySnapshot {
    page_session: String,
    frames: HashMap<String, FrameProof>,
    sessions: HashMap<String, SessionProof>,
    transforms: HashMap<String, Matrix>,
    clips: HashMap<String, Vec<Polygon>>,
    pub viewport: Viewport,
    semantic_frames: Option<SemanticFrameProof>,
}
#[derive(Debug, Clone)]
struct FrameInput {
    binding: element::ExactBinding,
    parent: Option<String>,
    owner: Option<i64>,
}
fn check(operation: &OperationLease) -> Result<(), GeometryError> {
    if *operation.cancellation.borrow() != CancelSignal::None {
        return Err(GeometryError::Cancelled);
    }
    if Instant::now() >= operation.deadline {
        return Err(GeometryError::DeadlineExceeded);
    }
    if super::client_observation::capture_superseded() {
        return Err(GeometryError::Superseded);
    }
    Ok(())
}
async fn command(
    client: &CdpClient,
    session: &str,
    method: &str,
    params: Value,
    operation: &OperationLease,
) -> Result<Value, GeometryError> {
    check(operation)?;
    super::client_debt::command_scope(
        super::client_debt::CommandCategory::ApplicationObject,
        false,
        super::client_observation::retained_read_command(
            client, session, method, params, operation,
        ),
    )
    .await
    .map_err(hidden_proof_error)
}
fn quad_points(value: &Value) -> Result<[Point; 4], GeometryError> {
    let values = value
        .as_array()
        .filter(|v| v.len() == 8)
        .ok_or(GeometryError::InvalidGeometry)?;
    let mut points = [Point { x: 0., y: 0. }; 4];
    for (index, p) in points.iter_mut().enumerate() {
        p.x = values[2 * index]
            .as_f64()
            .ok_or(GeometryError::InvalidGeometry)?;
        p.y = values[2 * index + 1]
            .as_f64()
            .ok_or(GeometryError::InvalidGeometry)?;
    }
    if points.iter().any(|p| !p.x.is_finite() || !p.y.is_finite()) {
        return Err(GeometryError::InvalidGeometry);
    }
    Ok(points)
}
fn quad(value: &Value) -> Result<[Point; 4], GeometryError> {
    let points = quad_points(value)?;
    validate_convex(&points)?;
    Ok(points)
}
fn number(value: &Value, key: &str) -> Result<f64, GeometryError> {
    value[key]
        .as_f64()
        .filter(|v| v.is_finite())
        .ok_or(GeometryError::InvalidGeometry)
}
fn metrics(value: &Value) -> Result<Viewport, GeometryError> {
    let visual = &value["cssVisualViewport"];
    let layout = &value["cssLayoutViewport"];
    let viewport = Viewport {
        width: number(visual, "clientWidth")?,
        height: number(visual, "clientHeight")?,
        offset_x: number(visual, "offsetX")?,
        offset_y: number(visual, "offsetY")?,
        scale: number(visual, "scale")?,
        layout_width: number(layout, "clientWidth")?,
        layout_height: number(layout, "clientHeight")?,
    };
    if viewport.width <= 0.
        || viewport.height <= 0.
        || viewport.scale <= 0.
        || viewport.layout_width <= 0.
        || viewport.layout_height <= 0.
    {
        return Err(GeometryError::InvalidGeometry);
    }
    Ok(viewport)
}
#[derive(Debug, Clone, PartialEq)]
struct TreeFrame {
    loader: String,
    url: Option<String>,
    parent: Option<String>,
}
fn tree_frames(tree: &Value) -> Result<HashMap<String, TreeFrame>, GeometryError> {
    let mut queue = vec![(tree, None::<String>)];
    let mut result = HashMap::new();
    while let Some((tree, structural_parent)) = queue.pop() {
        if result.len() >= MAX_FRAMES {
            return Err(GeometryError::IncompleteInventory);
        }
        let frame = &tree["frame"];
        let id = frame["id"]
            .as_str()
            .ok_or(GeometryError::IncompleteInventory)?;
        let loader = frame["loaderId"]
            .as_str()
            .ok_or(GeometryError::StaleIdentity)?;
        let declared_parent = frame["parentId"].as_str().map(str::to_owned);
        if structural_parent.is_some()
            && declared_parent.is_some()
            && structural_parent != declared_parent
        {
            return Err(GeometryError::StaleIdentity);
        }
        let parent = declared_parent.or(structural_parent);
        if result
            .insert(
                id.to_owned(),
                TreeFrame {
                    loader: loader.to_owned(),
                    url: frame["url"].as_str().map(str::to_owned),
                    parent,
                },
            )
            .is_some()
        {
            return Err(GeometryError::IncompleteInventory);
        }
        if let Some(children) = tree["childFrames"].as_array() {
            queue.extend(children.iter().map(|child| (child, Some(id.to_owned()))));
        }
    }
    Ok(result)
}
async fn read_proofs(
    client: &CdpClient,
    page_session: &str,
    inputs: &[FrameInput],
    excluded: &HashSet<String>,
    semantic: Option<&SemanticFrameProof>,
    operation: &OperationLease,
) -> Result<(HashMap<String, FrameProof>, HashMap<String, SessionProof>), GeometryError> {
    if inputs.is_empty() || inputs.len() > MAX_FRAMES {
        return Err(GeometryError::IncompleteInventory);
    }
    let mut frames = HashMap::new();
    let mut sessions = HashMap::new();
    let mut trees = HashMap::new();
    for input in inputs {
        let binding = &input.binding;
        if binding.page_session != page_session
            || binding.frame.is_empty()
            || binding.loader.is_empty()
            || frames.contains_key(&binding.frame)
        {
            return Err(GeometryError::IncompleteInventory);
        }
        frames.insert(
            binding.frame.clone(),
            FrameProof {
                id: binding.frame.clone(),
                loader: binding.loader.clone(),
                session: binding.session.clone(),
                parent: input.parent.clone(),
                owner: input.owner,
                owner_quad: None,
                owner_size: None,
            },
        );
        if !sessions.contains_key(&binding.session) {
            let tree = command(
                client,
                &binding.session,
                "Page.getFrameTree",
                json!({}),
                operation,
            )
            .await?;
            let root = tree["frameTree"]["frame"]["id"]
                .as_str()
                .ok_or(GeometryError::IncompleteInventory)?
                .to_owned();
            trees.insert(binding.session.clone(), tree_frames(&tree["frameTree"])?);
            let viewport = if inputs.iter().any(|input| {
                input.binding.session == binding.session && !excluded.contains(&input.binding.frame)
            }) {
                Some(metrics(
                    &command(
                        client,
                        &binding.session,
                        "Page.getLayoutMetrics",
                        json!({}),
                        operation,
                    )
                    .await?,
                )?)
            } else {
                None
            };
            sessions.insert(binding.session.clone(), SessionProof { root, viewport });
        }
    }
    for tree in trees.values() {
        if tree.keys().any(|id| !frames.contains_key(id)) {
            return Err(GeometryError::IncompleteInventory);
        }
    }
    let main = sessions
        .get(page_session)
        .ok_or(GeometryError::IncompleteInventory)?;
    if frames.get(&main.root).is_none_or(|f| f.parent.is_some())
        || frames.values().filter(|f| f.parent.is_none()).count() != 1
    {
        return Err(GeometryError::IncompleteInventory);
    }
    for session in sessions.values() {
        if !frames.contains_key(&session.root) {
            return Err(GeometryError::IncompleteInventory);
        }
    }
    for input in inputs {
        let binding = &input.binding;
        let native = trees
            .get(&binding.session)
            .and_then(|tree| tree.get(&binding.frame))
            .ok_or(GeometryError::StaleIdentity)?;
        if native.loader != binding.loader {
            return Err(GeometryError::StaleIdentity);
        }
        if let Some(proof) = semantic {
            // Use this same complete native acquisition, not a second CDP
            // round trip, to bind observation policy to the current URL.
            proof
                .validate_frame_url(binding, native.url.as_deref())
                .map_err(hidden_proof_error)?;
        }
        // A remote renderer root may omit parentId in its own tree. In that
        // case require its parent's native tree to declare the same edge.
        let native_parent = native.parent.as_ref().or_else(|| {
            trees
                .values()
                .filter_map(|tree| tree.get(&binding.frame))
                .find_map(|f| f.parent.as_ref())
        });
        if native_parent != input.parent.as_ref() {
            return Err(GeometryError::StaleIdentity);
        }
        if let Some(parent) = &input.parent {
            let parent = frames
                .get(parent)
                .ok_or(GeometryError::IncompleteInventory)?;
            let owner = command(
                client,
                &parent.session,
                "DOM.getFrameOwner",
                json!({"frameId":binding.frame}),
                operation,
            )
            .await?;
            let backend = owner["backendNodeId"]
                .as_i64()
                .ok_or(GeometryError::StaleIdentity)?;
            if Some(backend) != input.owner {
                return Err(GeometryError::StaleIdentity);
            }
            if excluded.contains(&binding.frame) {
                continue;
            }
            let parent_binding = element::ExactBinding {
                page_session: page_session.to_owned(),
                session: parent.session.clone(),
                frame: parent.id.clone(),
                loader: parent.loader.clone(),
                actionable: false,
            };
            let (model, size) = read_exact_box(
                client,
                &parent_binding,
                backend,
                operation,
                semantic.is_some(),
            )
            .await?;
            let size = size.ok_or(GeometryError::InvalidGeometry)?;
            let target = frames
                .get_mut(&binding.frame)
                .ok_or(GeometryError::IncompleteInventory)?;
            target.owner_quad = Some(quad(&model["model"]["content"])?);
            target.owner_size = Some(size);
        } else if input.owner.is_some() {
            return Err(GeometryError::IncompleteInventory);
        }
    }
    Ok((frames, sessions))
}
fn session_transform(
    session: &str,
    page: &str,
    frames: &HashMap<String, FrameProof>,
    sessions: &HashMap<String, SessionProof>,
    built: &mut HashMap<String, Matrix>,
    visiting: &mut HashSet<String>,
) -> Result<Matrix, GeometryError> {
    if let Some(matrix) = built.get(session) {
        return Ok(*matrix);
    }
    if visiting.len() >= MAX_FRAMES || !visiting.insert(session.to_owned()) {
        return Err(GeometryError::IncompleteInventory);
    }
    let proof = sessions
        .get(session)
        .ok_or(GeometryError::IncompleteInventory)?;
    let matrix = if session == page {
        Matrix::IDENTITY
    } else {
        let root = frames
            .get(&proof.root)
            .filter(|f| f.session == session)
            .ok_or(GeometryError::IncompleteInventory)?;
        let parent = frames
            .get(
                root.parent
                    .as_ref()
                    .ok_or(GeometryError::IncompleteInventory)?,
            )
            .ok_or(GeometryError::IncompleteInventory)?;
        if parent.session == session {
            return Err(GeometryError::IncompleteInventory);
        }
        let parent_matrix =
            session_transform(&parent.session, page, frames, sessions, built, visiting)?;
        let viewport = proof.viewport.ok_or(GeometryError::IncompleteInventory)?;
        // Native quads use renderer-root visual CSS coordinates. Offset moves
        // that origin back to the child layout viewport before embedding it in
        // the exact native content quad (border and padding are not viewport).
        Matrix::rectangle_to_quad(
            Bounds {
                x: -viewport.offset_x,
                y: -viewport.offset_y,
                width: root.owner_size.ok_or(GeometryError::IncompleteInventory)?.0,
                height: root.owner_size.ok_or(GeometryError::IncompleteInventory)?.1,
            },
            &root.owner_quad.ok_or(GeometryError::IncompleteInventory)?,
        )?
        .then(parent_matrix)?
    };
    visiting.remove(session);
    built.insert(session.to_owned(), matrix);
    Ok(matrix)
}
fn hidden_proof_error(error: ObservationError) -> GeometryError {
    match error {
        ObservationError::StaleReference
        | ObservationError::FrameNotFound(_)
        | ObservationError::FrameAmbiguous(_) => GeometryError::StaleIdentity,
        ObservationError::Cancelled => GeometryError::Cancelled,
        ObservationError::Superseded => GeometryError::Superseded,
        ObservationError::DeadlineExceeded => GeometryError::DeadlineExceeded,
        ObservationError::CleanupFailed { primary } => GeometryError::CleanupFailed {
            primary: primary.map(|error| Box::new(hidden_proof_error(*error))),
        },
        ObservationError::BackendFailure | ObservationError::UnsupportedCapability => {
            GeometryError::BackendFailure
        }
        ObservationError::InvalidArguments
        | ObservationError::PolicyDenied
        | ObservationError::ResourceLimit => GeometryError::IncompleteInventory,
    }
}
impl GeometrySnapshot {
    pub async fn capture(
        client: &CdpClient,
        page_session: &str,
        frames: &[ObservationFrame],
        operation: &OperationLease,
    ) -> Result<Self, GeometryError> {
        Self::capture_impl(client, page_session, frames, None, operation).await
    }
    /// Semantic-only omission requires the producer proof of the frozen policy,
    /// emitted document order/budget, and genuine hidden-owner evidence.
    /// The full topology remains verified; this never relaxes pixel/action quads.
    pub(crate) async fn capture_semantic(
        client: &CdpClient,
        page_session: &str,
        frames: &[ObservationFrame],
        proof: &SemanticFrameProof,
        policy: &ObservationFramePolicy,
        identity_scope: &str,
        revision: u64,
        operation: &OperationLease,
    ) -> Result<Self, GeometryError> {
        proof
            .validate_context(frames, policy, identity_scope, revision, operation)
            .map_err(hidden_proof_error)?;
        proof
            .revalidate(client, operation)
            .await
            .map_err(hidden_proof_error)?;
        Self::capture_impl(client, page_session, frames, Some(proof.clone()), operation).await
    }
    async fn capture_impl(
        client: &CdpClient,
        page_session: &str,
        frames: &[ObservationFrame],
        semantic_frames: Option<SemanticFrameProof>,
        operation: &OperationLease,
    ) -> Result<Self, GeometryError> {
        let empty = HashSet::new();
        let excluded = semantic_frames
            .as_ref()
            .map_or(&empty, SemanticFrameProof::excluded_frames);
        let inputs = frames
            .iter()
            .map(|f| FrameInput {
                binding: f.binding.clone(),
                parent: f.parent_frame_id.clone(),
                owner: f.owner_backend_id,
            })
            .collect::<Vec<_>>();
        let (frames, sessions) = read_proofs(
            client,
            page_session,
            &inputs,
            excluded,
            semantic_frames.as_ref(),
            operation,
        )
        .await?;
        let mut transforms = HashMap::new();
        for (session, proof) in &sessions {
            if proof.viewport.is_none() {
                continue;
            }
            session_transform(
                session,
                page_session,
                &frames,
                &sessions,
                &mut transforms,
                &mut HashSet::new(),
            )?;
        }
        let mut clips = HashMap::new();
        for frame in frames.values() {
            if excluded.contains(&frame.id) {
                continue;
            }
            let mut current = frame;
            let mut ancestors = Vec::new();
            let mut seen = HashSet::new();
            while let Some(parent_id) = &current.parent {
                if !seen.insert(current.id.clone()) || seen.len() > MAX_FRAMES {
                    return Err(GeometryError::IncompleteInventory);
                }
                let parent = frames
                    .get(parent_id)
                    .ok_or(GeometryError::IncompleteInventory)?;
                let transform = *transforms
                    .get(&parent.session)
                    .ok_or(GeometryError::IncompleteInventory)?;
                let quad = current
                    .owner_quad
                    .ok_or(GeometryError::IncompleteInventory)?;
                let projected = Polygon {
                    points: quad.to_vec(),
                    enclosure: None,
                }
                .transform(transform)?;
                ancestors.push(projected);
                current = parent;
            }
            clips.insert(frame.id.clone(), ancestors);
        }
        let viewport = sessions
            .get(page_session)
            .ok_or(GeometryError::IncompleteInventory)?
            .viewport
            .ok_or(GeometryError::IncompleteInventory)?;
        Ok(Self {
            page_session: page_session.to_owned(),
            frames,
            sessions,
            transforms,
            clips,
            viewport,
            semantic_frames,
        })
    }
    pub async fn revalidate(
        &self,
        client: &CdpClient,
        operation: &OperationLease,
    ) -> Result<(), GeometryError> {
        let inputs = self
            .frames
            .values()
            .map(|f| FrameInput {
                binding: element::ExactBinding {
                    page_session: self.page_session.clone(),
                    session: f.session.clone(),
                    frame: f.id.clone(),
                    loader: f.loader.clone(),
                    actionable: false,
                },
                parent: f.parent.clone(),
                owner: f.owner,
            })
            .collect::<Vec<_>>();
        if let Some(hidden) = &self.semantic_frames {
            hidden
                .revalidate(client, operation)
                .await
                .map_err(hidden_proof_error)?;
        }
        let empty = HashSet::new();
        let excluded = self
            .semantic_frames
            .as_ref()
            .map_or(&empty, SemanticFrameProof::excluded_frames);
        let (frames, sessions) = read_proofs(
            client,
            &self.page_session,
            &inputs,
            excluded,
            self.semantic_frames.as_ref(),
            operation,
        )
        .await?;
        if frames != self.frames || sessions != self.sessions {
            return Err(GeometryError::StaleIdentity);
        }
        Ok(())
    }
    /// Refresh layout after an intentional native scroll, never admitting a
    /// replacement document, renderer, owner, or newly appearing frame.
    pub async fn refresh_after_scroll(
        &self,
        client: &CdpClient,
        operation: &OperationLease,
    ) -> Result<Self, GeometryError> {
        if self.semantic_frames.is_some() {
            return Err(GeometryError::IncompleteInventory);
        }
        let inputs = self
            .frames
            .values()
            .map(|f| ObservationFrame {
                parent_frame_id: f.parent.clone(),
                owner_backend_id: f.owner,
                url: String::new(),
                offset_x: 0.,
                offset_y: 0.,
                frame_path: Vec::new(),
                binding: element::ExactBinding {
                    page_session: self.page_session.clone(),
                    session: f.session.clone(),
                    frame: f.id.clone(),
                    loader: f.loader.clone(),
                    actionable: false,
                },
            })
            .collect::<Vec<_>>();
        let fresh = Self::capture(client, &self.page_session, &inputs, operation).await?;
        if fresh.frames.len() != self.frames.len()
            || fresh.sessions.len() != self.sessions.len()
            || self.frames.iter().any(|(id, old)| {
                fresh.frames.get(id).is_none_or(|new| {
                    old.id != new.id
                        || old.loader != new.loader
                        || old.session != new.session
                        || old.parent != new.parent
                        || old.owner != new.owner
                })
            })
            || self.sessions.iter().any(|(id, old)| {
                fresh
                    .sessions
                    .get(id)
                    .is_none_or(|new| old.root != new.root)
            })
        {
            return Err(GeometryError::StaleIdentity);
        }
        Ok(fresh)
    }
    pub fn project_native_point(
        &self,
        frame_id: &str,
        point: Point,
    ) -> Result<Point, GeometryError> {
        self.check_input_viewports()?;
        let frame = self
            .frames
            .get(frame_id)
            .ok_or(GeometryError::IncompleteInventory)?;
        let transform = self
            .transforms
            .get(&frame.session)
            .ok_or(GeometryError::IncompleteInventory)?;
        transform.enclose(point)?;
        transform.apply(point)
    }
    /// Convert root Input coordinates to this frame's own DOM viewport. Native
    /// box quads are renderer-root coordinates, not local elementFromPoint input.
    pub fn root_to_frame_point(
        &self,
        frame_id: &str,
        point: Point,
    ) -> Result<Point, GeometryError> {
        let inverse = self.frame_local_transform(frame_id)?.inverse()?;
        inverse.enclose(point)?;
        inverse.apply(point)
    }
    pub fn frame_to_root_point(
        &self,
        frame_id: &str,
        point: Point,
    ) -> Result<Point, GeometryError> {
        let transform = self.frame_local_transform(frame_id)?;
        transform.enclose(point)?;
        transform.apply(point)
    }
    fn require_strict(&self) -> Result<(), GeometryError> {
        if self.semantic_frames.is_some() {
            return Err(GeometryError::IncompleteInventory);
        }
        Ok(())
    }
    fn require_included(&self, frame: &str) -> Result<(), GeometryError> {
        if self
            .semantic_frames
            .as_ref()
            .is_some_and(|proof| proof.excluded_frames().contains(frame))
        {
            return Err(GeometryError::IncompleteInventory);
        }
        Ok(())
    }
    fn check_input_viewports(&self) -> Result<(), GeometryError> {
        if self.semantic_frames.is_some() {
            return Err(GeometryError::IncompleteInventory);
        }
        if self.sessions.values().any(|s| {
            s.viewport
                .is_none_or(|v| v.scale != 1. || v.offset_x != 0. || v.offset_y != 0.)
        }) {
            return Err(GeometryError::InvalidGeometry);
        }
        Ok(())
    }
    fn frame_local_transform(&self, frame_id: &str) -> Result<Matrix, GeometryError> {
        // Pinch/visual-viewport coordinate convention needs its separate browser
        // proof. This is not a fallback to a guessed coordinate system.
        self.check_input_viewports()?;
        let frame = self
            .frames
            .get(frame_id)
            .ok_or(GeometryError::IncompleteInventory)?;
        let Some(parent_id) = &frame.parent else {
            return Ok(Matrix::IDENTITY);
        };
        let parent = self
            .frames
            .get(parent_id)
            .ok_or(GeometryError::IncompleteInventory)?;
        let size = frame.owner_size.ok_or(GeometryError::IncompleteInventory)?;
        Matrix::rectangle_to_quad(
            Bounds {
                x: 0.,
                y: 0.,
                width: size.0,
                height: size.1,
            },
            &frame.owner_quad.ok_or(GeometryError::IncompleteInventory)?,
        )?
        .then(
            *self
                .transforms
                .get(&parent.session)
                .ok_or(GeometryError::IncompleteInventory)?,
        )
    }
    /// Native-only exact owner chain for the capture paint-policy proof. This
    /// exposes no style/content and does not introduce another transform path.
    pub fn owner_chain(
        &self,
        frame_id: &str,
    ) -> Result<Vec<(element::ExactBinding, i64)>, GeometryError> {
        self.require_strict()?;
        self.require_included(frame_id)?;
        let mut frame = self
            .frames
            .get(frame_id)
            .ok_or(GeometryError::IncompleteInventory)?;
        let mut owners = Vec::new();
        let mut seen = HashSet::new();
        while let Some(parent) = &frame.parent {
            if !seen.insert(frame.id.clone()) || seen.len() > MAX_FRAMES {
                return Err(GeometryError::IncompleteInventory);
            }
            let owner = frame.owner.ok_or(GeometryError::IncompleteInventory)?;
            let parent = self
                .frames
                .get(parent)
                .ok_or(GeometryError::IncompleteInventory)?;
            owners.push((
                element::ExactBinding {
                    page_session: self.page_session.clone(),
                    session: parent.session.clone(),
                    frame: parent.id.clone(),
                    loader: parent.loader.clone(),
                    actionable: false,
                },
                owner,
            ));
            frame = parent;
        }
        Ok(owners)
    }
    pub fn clip_for_capture(
        &self,
        frame_id: &str,
        polygon: &Polygon,
    ) -> Result<Polygon, GeometryError> {
        self.require_strict()?;
        self.require_included(frame_id)?;
        let mut polygon = polygon.clone();
        for clip in self
            .clips
            .get(frame_id)
            .ok_or(GeometryError::IncompleteInventory)?
        {
            polygon = polygon.clip_proven(clip)?;
        }
        polygon.clip(
            &Bounds {
                x: 0.,
                y: 0.,
                width: self.viewport.width,
                height: self.viewport.height,
            }
            .corners(),
        )
    }
    pub fn project_native_quad(
        &self,
        frame_id: &str,
        points: [Point; 4],
    ) -> Result<Polygon, GeometryError> {
        self.require_strict()?;
        self.require_included(frame_id)?;
        validate_convex(&points)?;
        let frame = self
            .frames
            .get(frame_id)
            .ok_or(GeometryError::IncompleteInventory)?;
        let matrix = *self
            .transforms
            .get(&frame.session)
            .ok_or(GeometryError::IncompleteInventory)?;
        Polygon {
            enclosure: None,
            points: points.to_vec(),
        }
        .transform(matrix)
    }
    fn project_semantic_quad(
        &self,
        frame_id: &str,
        points: [Point; 4],
    ) -> Result<SemanticBounds, GeometryError> {
        self.require_included(frame_id)?;
        // Accept only the exact duplicate-edge form of a collapsed native
        // rectangle. Arbitrary collinear/bow-tie quads remain invalid.
        let collapsed = (points[0] == points[1] && points[2] == points[3])
            || (points[0] == points[3] && points[1] == points[2]);
        if !collapsed {
            validate_convex(&points)?;
        }
        if points.iter().any(|p| !p.x.is_finite() || !p.y.is_finite()) {
            return Err(GeometryError::InvalidGeometry);
        }
        let frame = self
            .frames
            .get(frame_id)
            .ok_or(GeometryError::IncompleteInventory)?;
        let matrix = *self
            .transforms
            .get(&frame.session)
            .ok_or(GeometryError::IncompleteInventory)?;
        // Reuse the same interval-checked transform/horizon proof, but expose
        // bounds only. Capture/action still require project_native_quad.
        let projected = Polygon {
            enclosure: None,
            points: points.to_vec(),
        }
        .transform(matrix)?;
        Ok(SemanticBounds(
            projected.bounds().ok_or(GeometryError::InvalidGeometry)?,
        ))
    }
    pub async fn node_semantic_bounds(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        backend: i64,
        operation: &OperationLease,
    ) -> Result<SemanticBounds, GeometryError> {
        self.require_included(&frame.binding.frame)?;
        let proof = self
            .frames
            .get(&frame.binding.frame)
            .ok_or(GeometryError::IncompleteInventory)?;
        if proof.session != frame.binding.session
            || proof.loader != frame.binding.loader
            || frame.binding.page_session != self.page_session
        {
            return Err(GeometryError::StaleIdentity);
        }
        let (model, _) =
            read_exact_box_impl(client, &frame.binding, backend, operation, false, true).await?;
        self.project_semantic_quad(
            &frame.binding.frame,
            quad_points(&model["model"]["border"])?,
        )
    }
    pub async fn node_border_polygons(
        &self,
        client: &CdpClient,
        frame: &ObservationFrame,
        backend: i64,
        operation: &OperationLease,
    ) -> Result<Vec<Polygon>, GeometryError> {
        self.require_strict()?;
        self.require_included(&frame.binding.frame)?;
        let proof = self
            .frames
            .get(&frame.binding.frame)
            .ok_or(GeometryError::IncompleteInventory)?;
        if proof.session != frame.binding.session
            || proof.loader != frame.binding.loader
            || frame.binding.page_session != self.page_session
        {
            return Err(GeometryError::StaleIdentity);
        }
        let (model, _) = read_exact_box(client, &frame.binding, backend, operation, false).await?;
        Ok(vec![self.project_native_quad(
            &frame.binding.frame,
            quad(&model["model"]["border"])?,
        )?])
    }
}

// Full used content-box size includes scrollbars and fractional CSS lengths.
// LayoutViewport.clientWidth is integer/excludes scrollbars and cannot be the
// source rectangle of a renderer boundary homography.
pub(crate) const BOX_PROOF: &str = r#"function(){
 const p=Node.prototype;const connected=Object.getOwnPropertyDescriptor(p,'isConnected').get.call(this)&&(this===document||Object.getOwnPropertyDescriptor(p,'ownerDocument').get.call(this)===document);
 if(!connected)return {connected:false};
 const frameOwner=this.nodeType===1&&(this.localName==='iframe'||this.localName==='frame');
 if(!frameOwner)return {connected:true,frameOwner:false};
 const s=getComputedStyle(this);let width=parseFloat(s.width),height=parseFloat(s.height);
 if(s.boxSizing==='border-box'){width-=parseFloat(s.paddingLeft)+parseFloat(s.paddingRight)+parseFloat(s.borderLeftWidth)+parseFloat(s.borderRightWidth);height-=parseFloat(s.paddingTop)+parseFloat(s.paddingBottom)+parseFloat(s.borderTopWidth)+parseFloat(s.borderBottomWidth);}
 return {connected:true,frameOwner:true,width,height};
}"#;
async fn read_exact_box(
    client: &CdpClient,
    binding: &element::ExactBinding,
    backend: i64,
    operation: &OperationLease,
    readonly_disposal: bool,
) -> Result<(Value, Option<(f64, f64)>), GeometryError> {
    read_exact_box_impl(client, binding, backend, operation, true, readonly_disposal).await
}
async fn read_exact_box_impl(
    client: &CdpClient,
    binding: &element::ExactBinding,
    backend: i64,
    operation: &OperationLease,
    require_owner_size: bool,
    readonly_disposal: bool,
) -> Result<(Value, Option<(f64, f64)>), GeometryError> {
    check(operation)?;
    if readonly_disposal
        && client.debt_ledger().is_some()
        && super::client_debt::OperationJournalHandle::current().is_some()
    {
        // A group, not a textual objectId, owns this complete readonly read.
        // Never reuse its name while an earlier release is queued or unacked.
        let group = client
            .readonly_group_instance(&format!("native-semantic-box-{}", operation.sequence))
            .map_err(|_| GeometryError::BackendFailure)?;
        let result = super::client_debt::native_object_group(
            &group,
            read_exact_box_inner(
                client,
                binding,
                backend,
                operation,
                require_owner_size,
                Some(&group),
            ),
        )
        .await;
        if super::client_actions::release_readonly_group_accounted(client, &binding.session, &group)
            .await
        {
            return result;
        }
        return Err(GeometryError::CleanupFailed {
            primary: result.err().map(Box::new),
        });
    }
    read_exact_box_inner(
        client,
        binding,
        backend,
        operation,
        require_owner_size,
        None,
    )
    .await
}
async fn read_exact_box_inner(
    client: &CdpClient,
    binding: &element::ExactBinding,
    backend: i64,
    operation: &OperationLease,
    require_owner_size: bool,
    readonly_group: Option<&str>,
) -> Result<(Value, Option<(f64, f64)>), GeometryError> {
    check(operation)?;
    let mut cancel = operation.cancellation.clone();
    let resolution = async {
        match readonly_group {
            Some(group) => {
                element::resolve_exact_object_in_readonly_group(client, binding, backend, group)
                    .await
            }
            None => element::resolve_exact_object_typed(client, binding, backend).await,
        }
    };
    tokio::pin!(resolution);
    let (resolved, interrupted) = tokio::select! {
        result=&mut resolution=>(Some(result),None),
        _=cancel.changed()=>(None,Some(GeometryError::Cancelled)),
        _=tokio::time::sleep_until(operation.deadline.into())=>(None,Some(GeometryError::DeadlineExceeded)),
    };
    let resolved = match resolved {
        Some(result) => result,
        None => match tokio::time::timeout(Duration::from_millis(250), &mut resolution).await {
            Ok(result) => result,
            Err(_) => {
                if super::client_debt::OperationJournalHandle::current()
                    .is_some_and(|journal| journal.has_accounted_object_creation(&binding.session))
                {
                    return Err(interrupted.unwrap_or(GeometryError::Cancelled));
                }
                return Err(GeometryError::CleanupFailed {
                    primary: interrupted.map(Box::new),
                });
            }
        },
    };
    let object = resolved.map_err(|error| match error {
        // The strict resolver released acquired objects; readonly resolution
        // leaves them with the outer exact group owner. Neither case converts
        // retirement into success. Preserve cancellation already observed here.
        element::ExactResolutionError::Superseded => {
            check(operation).err().unwrap_or(GeometryError::Superseded)
        }
        _ => GeometryError::CleanupFailed {
            primary: Some(Box::new(
                interrupted.clone().unwrap_or(GeometryError::StaleIdentity),
            )),
        },
    })?;
    if let Some(primary) = interrupted {
        return if readonly_group.is_some()
            || super::client_actions::release_object_accounted(client, &binding.session, &object)
                .await
        {
            Err(primary)
        } else {
            Err(GeometryError::CleanupFailed {
                primary: Some(Box::new(primary)),
            })
        };
    }
    let mut owned_objects = vec![object.clone()];
    let result = async {
        let model = command(
            client,
            &binding.session,
            "DOM.getBoxModel",
            json!({"objectId":object}),
            operation,
        )
        .await?;
        // Recheck the same object against the isolated realm document after
        // geometry, not merely the frame loader: adoption can keep a node connected.
        let mut params =
            json!({"objectId":object,"functionDeclaration":BOX_PROOF,"returnByValue":true});
        if let Some(group) = readonly_group {
            params["objectGroup"] = group.into();
        }
        let proof = command(
            client,
            &binding.session,
            "Runtime.callFunctionOn",
            params,
            operation,
        )
        .await?;
        for value in [
            &proof["result"]["objectId"],
            &proof["exceptionDetails"]["exception"]["objectId"],
        ] {
            if let Some(id) = value.as_str() {
                if !owned_objects.iter().any(|owned| owned == id) {
                    owned_objects.push(id.to_owned());
                }
            }
        }
        if proof.get("exceptionDetails").is_some() || proof["result"]["value"]["connected"] != true
        {
            return Err(GeometryError::StaleIdentity);
        }
        let value = &proof["result"]["value"];
        let size = if require_owner_size && value["frameOwner"] == true {
            let w = number(value, "width")?;
            let h = number(value, "height")?;
            if w <= 0. || h <= 0. {
                return Err(GeometryError::InvalidGeometry);
            }
            Some((w, h))
        } else {
            None
        };
        Ok((model, size))
    }
    .await;
    if readonly_group.is_some() {
        // The outer group owner releases successful, refused and auxiliary
        // handles together. It never transfers a staged action reference.
        return result;
    }
    let released = tokio::time::timeout(Duration::from_millis(250), async {
        let mut complete = true;
        for object in owned_objects {
            if !super::client_actions::release_object_accounted(client, &binding.session, &object)
                .await
            {
                complete = false;
            }
        }
        complete
    })
    .await;
    if !matches!(released, Ok(true)) {
        return Err(GeometryError::CleanupFailed {
            primary: result.err().map(Box::new),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rect(x: f64, y: f64, width: f64, height: f64) -> [Point; 4] {
        Bounds {
            x,
            y,
            width,
            height,
        }
        .corners()
    }
    fn viewport() -> Viewport {
        Viewport {
            width: 100.,
            height: 80.,
            offset_x: 0.,
            offset_y: 0.,
            scale: 1.,
            layout_width: 100.,
            layout_height: 80.,
        }
    }
    #[test]
    fn inverse_points_preserve_affine_and_projective_coordinates() {
        for m in [
            Matrix::exact([[2., 0., 15.], [0., 3., -7.], [0., 0., 1.]]),
            Matrix::rectangle_to_quad(
                Bounds {
                    x: 0.,
                    y: 0.,
                    width: 100.,
                    height: 100.,
                },
                &[
                    Point { x: 0., y: 0. },
                    Point { x: 200., y: 0. },
                    Point { x: 150., y: 100. },
                    Point { x: 50., y: 100. },
                ],
            )
            .unwrap(),
        ] {
            let inverse = m.inverse().unwrap();
            for original in [
                Point { x: 0., y: 0. },
                Point { x: 25., y: 75. },
                Point { x: 100., y: 100. },
            ] {
                let mapped = m.apply(original).unwrap();
                let back = inverse.apply(mapped).unwrap();
                assert!((back.x - original.x).abs() <= gamma(64) * 100.);
                assert!((back.y - original.y).abs() <= gamma(64) * 100.);
            }
        }
        assert_eq!(
            Matrix::exact([[1., 0., 0.], [1., 0., 0.], [0., 0., 1.]]).inverse(),
            Err(GeometryError::InvalidGeometry)
        );
    }
    #[test]
    fn frame_local_inverse_does_not_double_compose_same_renderer_ancestors() {
        let main = FrameProof {
            id: "main".into(),
            loader: "l1".into(),
            session: "page".into(),
            parent: None,
            owner: None,
            owner_quad: None,
            owner_size: None,
        };
        let child = FrameProof {
            id: "child".into(),
            loader: "l2".into(),
            session: "page".into(),
            parent: Some("main".into()),
            owner: Some(7),
            owner_quad: Some(rect(100., 200., 200., 100.)),
            owner_size: Some((100., 50.)),
        };
        // Native owner quad already includes same-renderer ancestor transforms.
        let leaf = FrameProof {
            id: "leaf".into(),
            loader: "l3".into(),
            session: "page".into(),
            parent: Some("child".into()),
            owner: Some(8),
            owner_quad: Some(rect(120., 230., 40., 20.)),
            owner_size: Some((40., 20.)),
        };
        let mut proof = GeometrySnapshot {
            page_session: "page".into(),
            frames: [main, child, leaf]
                .into_iter()
                .map(|f| (f.id.clone(), f))
                .collect(),
            sessions: HashMap::from([(
                "page".into(),
                SessionProof {
                    root: "main".into(),
                    viewport: Some(viewport()),
                },
            )]),
            transforms: HashMap::from([("page".into(), Matrix::IDENTITY)]),
            clips: HashMap::new(),
            viewport: viewport(),
            semantic_frames: None,
        };
        let root = proof
            .frame_to_root_point("leaf", Point { x: 5., y: 7. })
            .unwrap();
        assert_eq!(root, Point { x: 125., y: 237. });
        assert_eq!(
            proof.root_to_frame_point("leaf", root).unwrap(),
            Point { x: 5., y: 7. }
        );
        assert_eq!(
            proof.root_to_frame_point("child", root).unwrap(),
            Point { x: 12.5, y: 18.5 }
        );
        assert_eq!(proof.project_native_point("leaf", root).unwrap(), root);
        proof
            .sessions
            .get_mut("page")
            .unwrap()
            .viewport
            .as_mut()
            .unwrap()
            .scale = 2.;
        assert_eq!(
            proof.project_native_point("leaf", root),
            Err(GeometryError::InvalidGeometry)
        );
        assert_eq!(
            proof.root_to_frame_point("leaf", root),
            Err(GeometryError::InvalidGeometry)
        );
    }
    #[test]
    fn affine_composition_applies_nested_renderer_boundary_once() {
        let outer = Matrix::rectangle_to_quad(
            Bounds {
                x: 0.,
                y: 0.,
                width: 200.,
                height: 100.,
            },
            &rect(40., 30., 400., 200.),
        )
        .unwrap();
        let inner = Matrix::rectangle_to_quad(
            Bounds {
                x: 0.,
                y: 0.,
                width: 100.,
                height: 50.,
            },
            &rect(10., 15., 100., 50.),
        )
        .unwrap();
        assert_eq!(
            inner
                .then(outer)
                .unwrap()
                .apply(Point { x: 5., y: 7. })
                .unwrap(),
            Point { x: 70., y: 74. }
        );
        // A same-renderer native quad already includes the inner transform.
        assert_eq!(
            outer.apply(Point { x: 15., y: 22. }).unwrap(),
            Point { x: 70., y: 74. }
        );
    }
    #[test]
    fn projective_quad_maps_corners_and_independent_center() {
        let q = [
            Point { x: 0., y: 0. },
            Point { x: 200., y: 0. },
            Point { x: 150., y: 100. },
            Point { x: 50., y: 100. },
        ];
        let m = Matrix::rectangle_to_quad(
            Bounds {
                x: 0.,
                y: 0.,
                width: 100.,
                height: 100.,
            },
            &q,
        )
        .unwrap();
        // Independently: intersection of the trapezoid diagonals is (100, 200/3).
        let p = m.apply(Point { x: 50., y: 50. }).unwrap();
        assert!((p.x - 100.).abs() <= gamma(8) * 100.);
        assert!((p.y - 200. / 3.).abs() <= gamma(8) * 100.);
    }
    #[test]
    fn rotated_reflected_and_fractional_quads_preserve_orientation() {
        for q in [
            [
                Point { x: 10., y: 20. },
                Point { x: 10., y: 120. },
                Point { x: -40., y: 120. },
                Point { x: -40., y: 20. },
            ],
            rect(0.25, 0.5, 25.5, 12.25),
            [
                Point { x: 100., y: 0. },
                Point { x: 0., y: 0. },
                Point { x: 0., y: 50. },
                Point { x: 100., y: 50. },
            ],
        ] {
            let source = Bounds {
                x: -2.,
                y: -3.,
                width: 100.,
                height: 50.,
            };
            let m = Matrix::rectangle_to_quad(source, &q).unwrap();
            for (a, b) in source.corners().iter().zip(q) {
                let p = m.apply(*a).unwrap();
                assert!((p.x - b.x).abs() <= gamma(64) * (1. + b.x.abs()));
                assert!((p.y - b.y).abs() <= gamma(64) * (1. + b.y.abs()));
            }
        }
    }
    #[test]
    fn child_visual_offset_is_not_document_scroll() {
        let m = Matrix::rectangle_to_quad(
            Bounds {
                x: -10.,
                y: -20.,
                width: 200.,
                height: 100.,
            },
            &rect(30., 40., 200., 100.),
        )
        .unwrap();
        assert_eq!(
            m.apply(Point { x: 0., y: 0. }).unwrap(),
            Point { x: 40., y: 60. }
        );
        // Document scroll is already included in the native element quad.
        assert_eq!(
            m.apply(Point { x: -5., y: -7. }).unwrap(),
            Point { x: 35., y: 53. }
        );
    }
    #[test]
    fn clipping_keeps_polygon_until_outward_rasterization() {
        let diamond = Polygon {
            enclosure: None,
            points: vec![
                Point { x: 50., y: -20. },
                Point { x: 120., y: 40. },
                Point { x: 50., y: 100. },
                Point { x: -20., y: 40. },
            ],
        };
        let clipped = diamond.clip(&rect(0., 0., 100., 80.)).unwrap();
        assert_eq!(clipped.points.len(), 8);
        assert_eq!(
            clipped.bounds().unwrap(),
            Bounds {
                x: 0.,
                y: 0.,
                width: 100.,
                height: 80.
            }
        );
        assert_eq!(
            clipped.raster_bounds(viewport(), 200, 160).unwrap(),
            Some(PixelBounds {
                left: 0,
                top: 0,
                right: 200,
                bottom: 160
            })
        );
    }
    #[test]
    fn fractional_masks_use_actual_bitmap_scale_without_extra_integer_border() {
        let p = Polygon {
            enclosure: None,
            points: rect(10.25, 20.125, 5.5, 3.25).to_vec(),
        };
        assert_eq!(
            p.raster_bounds(viewport(), 200, 240).unwrap(),
            Some(PixelBounds {
                left: 20,
                top: 60,
                right: 32,
                bottom: 71
            })
        );
        let p = Polygon {
            enclosure: None,
            points: rect(10., 20., 5., 3.).to_vec(),
        };
        assert_eq!(
            p.raster_bounds(viewport(), 100, 80).unwrap(),
            Some(PixelBounds {
                left: 10,
                top: 20,
                right: 15,
                bottom: 23
            })
        );
    }
    #[test]
    fn empty_clipping_is_not_an_all_black_mask() {
        let p = Polygon {
            enclosure: None,
            points: rect(200., 200., 5., 5.).to_vec(),
        }
        .clip(&rect(0., 0., 100., 80.))
        .unwrap();
        assert_eq!(p.raster_bounds(viewport(), 100, 80).unwrap(), None);
    }
    #[test]
    fn degenerate_nonfinite_bowtie_and_horizon_fail_closed() {
        let source = Bounds {
            x: 0.,
            y: 0.,
            width: 100.,
            height: 50.,
        };
        for q in [
            rect(0., 0., 0., 50.),
            [
                Point { x: 0., y: 0. },
                Point { x: 100., y: 50. },
                Point { x: 100., y: 0. },
                Point { x: 0., y: 50. },
            ],
            rect(f64::NAN, 0., 100., 50.),
        ] {
            assert_eq!(
                Matrix::rectangle_to_quad(source, &q),
                Err(GeometryError::InvalidGeometry)
            );
        }
        assert_eq!(
            Matrix::exact([[1., 0., 0.], [0., 1., 0.], [1., 0., -1.]])
                .apply(Point { x: 1., y: 0. }),
            Err(GeometryError::InvalidGeometry)
        );
    }
    #[test]
    fn finite_vertices_do_not_hide_a_projective_horizon_between_them() {
        let p = Polygon {
            points: rect(-1., -1., 2., 2.).to_vec(),
            enclosure: None,
        };
        let m = Matrix::exact([[1., 0., 1.], [0., 1., 0.], [1., 0., 0.]]);
        assert!(p.points.iter().all(|point| m.apply(*point).is_ok()));
        assert_eq!(p.transform(m), Err(GeometryError::InvalidGeometry));
    }
    #[test]
    fn native_quad_parser_rejects_partial_and_nonfinite_data() {
        assert_eq!(
            quad(&json!([0, 0, 1, 0, 1, 1])),
            Err(GeometryError::InvalidGeometry)
        );
        assert_eq!(
            quad(&json!([0, 0, 1, 0, 1, 1, 0, 1])).unwrap(),
            rect(0., 0., 1., 1.)
        );
    }
    #[test]
    fn fractional_frame_source_size_is_not_scrollbar_excluding_integer_viewport() {
        let frame = FrameProof {
            id: "child".into(),
            loader: "child-doc".into(),
            session: "child-session".into(),
            parent: Some("root".into()),
            owner: Some(9),
            owner_quad: Some(rect(20., 30., 200.5, 80.)),
            owner_size: Some((100.25, 40.)),
        };
        let root = FrameProof {
            id: "root".into(),
            loader: "doc".into(),
            session: "page".into(),
            parent: None,
            owner: None,
            owner_quad: None,
            owner_size: None,
        };
        let frames = HashMap::from([("root".into(), root), ("child".into(), frame)]);
        let sessions = HashMap::from([
            (
                "page".into(),
                SessionProof {
                    root: "root".into(),
                    viewport: Some(viewport()),
                },
            ),
            (
                "child-session".into(),
                SessionProof {
                    root: "child".into(),
                    viewport: Some(Viewport {
                        width: 85.,
                        height: 40.,
                        layout_width: 85.,
                        layout_height: 40.,
                        ..viewport()
                    }),
                },
            ),
        ]);
        let m = session_transform(
            "child-session",
            "page",
            &frames,
            &sessions,
            &mut HashMap::new(),
            &mut HashSet::new(),
        )
        .unwrap();
        assert_eq!(
            m.apply(Point { x: 3., y: 5. }).unwrap(),
            Point { x: 26., y: 40. }
        );
    }
    #[test]
    fn directed_intervals_cover_nonbinary_division_and_exact_integer_operations() {
        let third = Interval::exact(1.).div(Interval::exact(3.)).unwrap();
        assert!(third.lo < third.hi);
        let one = third.mul(Interval::exact(3.));
        assert!(one.lo <= 1. && one.hi >= 1.);
        assert_eq!(
            Interval::exact(10.)
                .mul(Interval::exact(2.))
                .add(Interval::exact(0.5)),
            Interval::exact(20.5)
        );
        assert_eq!(
            Interval::exact(1.).div(Interval { lo: -1., hi: 1. }),
            Err(GeometryError::InvalidGeometry)
        );
    }
    #[test]
    fn native_tree_parent_edges_cannot_be_replaced_by_caller_claims() {
        let tree = json!({"frame":{"id":"root","loaderId":"r"},"childFrames":[{"frame":{"id":"child","loaderId":"c","parentId":"wrong"}}]});
        assert_eq!(tree_frames(&tree), Err(GeometryError::StaleIdentity));
        let tree = json!({"frame":{"id":"root","loaderId":"r"},"childFrames":[{"frame":{"id":"child","loaderId":"c"}}]});
        assert_eq!(
            tree_frames(&tree).unwrap()["child"].parent.as_deref(),
            Some("root")
        );
    }
    type MockLog = std::sync::Arc<std::sync::Mutex<Vec<Value>>>;
    async fn mock_geometry(
        fail_post_proof: bool,
    ) -> (
        CdpClient,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        MockLog,
    ) {
        mock_geometry_with_border(fail_post_proof, json!([10, 20, 30, 20, 30, 40, 10, 40])).await
    }
    async fn mock_geometry_with_border(
        fail_post_proof: bool,
        border: Value,
    ) -> (
        CdpClient,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        MockLog,
    ) {
        use futures_util::{SinkExt, StreamExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let moved = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let changed = moved.clone();
        let log = MockLog::default();
        let server_log = log.clone();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut calls = 0;
            while let Some(Ok(message)) = socket.next().await {
                let Ok(text) = message.to_text() else {
                    continue;
                };
                let request: Value = serde_json::from_str(text).unwrap();
                server_log.lock().unwrap().push(request.clone());
                let result = match request["method"].as_str().unwrap() {
                    "Page.getFrameTree" => {
                        json!({"frameTree":{"frame":{"id":"root","loaderId":"doc"}}})
                    }
                    "Page.getLayoutMetrics" => {
                        json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":if changed.load(std::sync::atomic::Ordering::SeqCst){1}else{0},"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                    }
                    "Page.createIsolatedWorld" => json!({"executionContextId":3}),
                    "DOM.resolveNode" => {
                        json!({"object":{"objectId":"owned-node","subtype":"node"}})
                    }
                    "DOM.getBoxModel" => json!({"model":{"border":border}}),
                    "Runtime.callFunctionOn" => {
                        calls += 1;
                        if fail_post_proof && calls == 2 {
                            json!({"result":{"objectId":"result-owned"},"exceptionDetails":{"exception":{"objectId":"exception-owned"}}})
                        } else {
                            if request["params"]["functionDeclaration"] != BOX_PROOF {
                                json!({"result":{"value":true}})
                            } else {
                                json!({"result":{"value":{"connected":true,"frameOwner":false}}})
                            }
                        }
                    }
                    _ => json!({}),
                };
                if socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        json!({"id":request["id"],"result":result}).to_string(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        (CdpClient::connect(&url).await.unwrap(), task, moved, log)
    }
    fn mock_frame() -> ObservationFrame {
        ObservationFrame {
            parent_frame_id: None,
            owner_backend_id: None,
            url: "https://synthetic.invalid/".into(),
            binding: element::ExactBinding {
                page_session: "page".into(),
                session: "page".into(),
                frame: "root".into(),
                loader: "doc".into(),
                actionable: false,
            },
            offset_x: 999.,
            offset_y: 999.,
            frame_path: vec![],
        }
    }
    fn mock_operation() -> (OperationLease, tokio::sync::watch::Sender<CancelSignal>) {
        let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        (
            OperationLease {
                is_callback: false,
                generation: 1,
                sequence: 5,
                deadline: Instant::now() + Duration::from_secs(5),
                cancellation,
            },
            sender,
        )
    }
    #[tokio::test]
    async fn semantic_exclusion_preserves_full_native_ownership_without_spatial_reads() {
        use futures_util::{SinkExt, StreamExt};
        use std::sync::{Arc, Mutex};
        for (child_session, hidden_owner) in [
            ("page", true),
            ("remote", true),
            ("page", false),
            ("remote", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}", listener.local_addr().unwrap());
            let log = Arc::new(Mutex::new(Vec::<Value>::new()));
            let requests = log.clone();
            let hidden = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let reported_hidden = hidden.clone();
            let url_changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reported_url_changed = url_changed.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    let request: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                    requests.lock().unwrap().push(request.clone());
                    let child_url =
                        if reported_url_changed.load(std::sync::atomic::Ordering::SeqCst) {
                            "about:srcdoc"
                        } else {
                            "https://synthetic.invalid/"
                        };
                    let result = match request["method"].as_str().unwrap() {
                        "Page.getFrameTree" if request["sessionId"] == "remote" => {
                            json!({"frameTree":{"frame":{"id":"child","loaderId":"child-doc","url":child_url,"parentId":"root"}}})
                        }
                        "Page.getFrameTree" => {
                            json!({"frameTree":{"frame":{"id":"root","loaderId":"doc","url":"https://synthetic.invalid/"},"childFrames":[{"frame":{"id":"child","loaderId":"child-doc","url":child_url}}]}})
                        }
                        "Page.getLayoutMetrics" => {
                            json!({"cssVisualViewport":{"clientWidth":100,"clientHeight":80,"offsetX":0,"offsetY":0,"scale":1},"cssLayoutViewport":{"clientWidth":100,"clientHeight":80}})
                        }
                        "DOM.getFrameOwner" => json!({"backendNodeId":7}),
                        "Page.createIsolatedWorld" => json!({"executionContextId":3}),
                        "DOM.resolveNode" => {
                            json!({"object":{"objectId":"owner","subtype":"node"}})
                        }
                        "Runtime.callFunctionOn"
                            if request["params"]["functionDeclaration"]
                                .as_str()
                                .is_some_and(|function| {
                                    function.starts_with("function(testId,secureSelector)")
                                }) =>
                        {
                            json!({"result":{"value":{"nodeType":1,"tag":"iframe","hidden":reported_hidden.load(std::sync::atomic::Ordering::SeqCst)}}})
                        }
                        "Runtime.callFunctionOn" => {
                            json!({"result":{"value":{"connected":true,"frameOwner":true,"width":0,"height":0}}})
                        }
                        "DOM.getBoxModel" => json!({"model":{"content":[0,0,0,0,0,0,0,0]}}),
                        _ => json!({}),
                    };
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            json!({"id":request["id"],"result":result}).to_string(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let client = CdpClient::connect(&url).await.unwrap();
            let (operation, _cancel) = mock_operation();
            let main = mock_frame();
            let mut child = main.clone();
            child.parent_frame_id = Some("root".into());
            child.owner_backend_id = Some(7);
            child.binding.frame = "child".into();
            child.binding.loader = "child-doc".into();
            child.binding.session = child_session.into();
            let inputs = [main.clone(), child.clone()].map(|frame| FrameInput {
                binding: frame.binding,
                parent: frame.parent_frame_id,
                owner: frame.owner_backend_id,
            });
            let excluded = HashSet::from(["child".into()]);
            let (frames, sessions) =
                read_proofs(&client, "page", &inputs, &excluded, None, &operation)
                    .await
                    .unwrap();
            assert_eq!(frames.len(), 2);
            assert_eq!(frames["child"].owner, Some(7));
            assert_eq!(frames["child"].owner_quad, None);
            if child_session == "remote" {
                assert_eq!(sessions["remote"].viewport, None);
            }
            let requests = log.lock().unwrap().clone();
            assert!(requests.iter().any(|r| r["method"] == "DOM.getFrameOwner"));
            assert!(!requests
                .iter()
                .any(|r| r["method"] == "DOM.getBoxModel" || r["method"] == "DOM.resolveNode"));
            assert!(!requests
                .iter()
                .any(|r| r["method"] == "Page.getLayoutMetrics" && r["sessionId"] == "remote"));
            let full = [main.clone(), child.clone()];
            let semantic_proof = SemanticFrameProof::for_test(
                &full,
                if hidden_owner { &["child"] } else { &[] },
                "fixture",
                1,
                &operation,
            );
            let semantic = GeometrySnapshot::capture_semantic(
                &client,
                "page",
                &full,
                &semantic_proof,
                &ObservationFramePolicy::default(),
                "fixture",
                1,
                &operation,
            )
            .await
            .unwrap();
            semantic.revalidate(&client, &operation).await.unwrap();
            assert!(semantic
                .project_semantic_quad("root", rect(1., 2., 3., 4.))
                .is_ok());
            assert_eq!(
                semantic.project_semantic_quad("child", rect(1., 2., 3., 4.)),
                Err(GeometryError::IncompleteInventory)
            );
            assert_eq!(
                semantic.project_native_quad("root", rect(1., 2., 3., 4.)),
                Err(GeometryError::IncompleteInventory)
            );
            assert_eq!(
                semantic.owner_chain("child"),
                Err(GeometryError::IncompleteInventory)
            );
            assert_eq!(
                semantic
                    .node_semantic_bounds(&client, &child, 9, &operation)
                    .await,
                Err(GeometryError::IncompleteInventory)
            );
            // Same-document location changes cannot reuse the old semantic
            // site decision, including when the whole renderer was omitted.
            url_changed.store(true, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                semantic.revalidate(&client, &operation).await,
                Err(GeometryError::StaleIdentity)
            );
            url_changed.store(false, std::sync::atomic::Ordering::SeqCst);
            hidden.store(false, std::sync::atomic::Ordering::SeqCst);
            if hidden_owner {
                assert_eq!(
                    semantic.revalidate(&client, &operation).await,
                    Err(GeometryError::StaleIdentity)
                );
            } else {
                // Policy omission is not claimed hidden; a visibility change
                // cannot invalidate or manufacture its independent proof.
                semantic.revalidate(&client, &operation).await.unwrap();
            }
            let mut wrong = inputs.clone();
            wrong[1].owner = Some(8);
            assert_eq!(
                read_proofs(&client, "page", &wrong, &excluded, None, &operation)
                    .await
                    .unwrap_err(),
                GeometryError::StaleIdentity
            );
            let mut replaced = inputs.clone();
            replaced[1].binding.loader = "replacement".into();
            assert_eq!(
                read_proofs(&client, "page", &replaced, &excluded, None, &operation)
                    .await
                    .unwrap_err(),
                GeometryError::StaleIdentity
            );
            assert_eq!(
                read_proofs(&client, "page", &inputs[..1], &excluded, None, &operation)
                    .await
                    .unwrap_err(),
                GeometryError::IncompleteInventory
            );
            assert!(
                GeometrySnapshot::capture(&client, "page", &[main, child], &operation)
                    .await
                    .is_err(),
                "strict geometry must still refuse collapsed owner"
            );
            server.abort();
        }
    }
    #[test]
    fn hidden_proof_cleanup_keeps_original_failure() {
        assert_eq!(
            hidden_proof_error(ObservationError::UnsupportedCapability),
            GeometryError::BackendFailure
        );
        assert_eq!(
            hidden_proof_error(ObservationError::CleanupFailed {
                primary: Some(Box::new(ObservationError::Cancelled))
            }),
            GeometryError::CleanupFailed {
                primary: Some(Box::new(GeometryError::Cancelled))
            }
        );
    }
    #[tokio::test]
    async fn semantic_projection_keeps_zero_area_bounds_without_granting_paint_authority() {
        for (border, width, height) in [
            (json!([10, 20, 10, 20, 10, 20, 10, 20]), 0., 0.),
            (json!([10, 20, 10, 20, 10, 40, 10, 40]), 0., 20.),
            (json!([10, 20, 30, 20, 30, 20, 10, 20]), 20., 0.),
        ] {
            let (client, server, _, _) = mock_geometry_with_border(false, border.clone()).await;
            let (operation, _sender) = mock_operation();
            let frame = mock_frame();
            let geometry = GeometrySnapshot::capture(
                &client,
                "page",
                std::slice::from_ref(&frame),
                &operation,
            )
            .await
            .unwrap();
            let mut refs = element::RefMap::new();
            let id = refs
                .try_bind_exact(7, "generic", "", frame.binding.clone())
                .unwrap();
            let mut node = super::super::client_observation::SemanticNode::default();
            node.reference.id = format!("@{id}");
            node.reference.revision = "1".into();
            node.rect = Some(super::super::client_observation::Rect {
                x: 999.,
                y: 999.,
                width,
                height,
            });
            let mut nodes = vec![node];
            // This is the exact post-read projection used by dispatch, not a
            // metadata-only assertion that bypasses native geometry.
            super::super::client_observation::project_geometry(
                &client,
                std::slice::from_ref(&frame),
                &refs,
                &geometry,
                &mut nodes,
                &operation,
            )
            .await
            .unwrap();
            let rect = nodes[0].rect.as_ref().unwrap();
            assert_eq!(
                (rect.x, rect.y, rect.width, rect.height),
                (10., 20., width, height)
            );
            assert_eq!(
                geometry.project_native_quad("root", quad_points(&border).unwrap()),
                Err(GeometryError::InvalidGeometry)
            );
            geometry.revalidate(&client, &operation).await.unwrap();
            server.abort();
            let _ = server.await;
        }
    }
    #[tokio::test]
    async fn semantic_degenerate_bounds_retain_transform_and_reject_nonrectangular_collapse() {
        let (client, server, _, _) = mock_geometry(false).await;
        let (operation, _sender) = mock_operation();
        let frame = mock_frame();
        let mut geometry =
            GeometrySnapshot::capture(&client, "page", std::slice::from_ref(&frame), &operation)
                .await
                .unwrap();
        geometry.transforms.insert(
            "page".into(),
            Matrix::rectangle_to_quad(
                Bounds {
                    x: 0.,
                    y: 0.,
                    width: 100.,
                    height: 100.,
                },
                &[
                    Point { x: 20., y: 30. },
                    Point { x: 220., y: 30. },
                    Point { x: 220., y: 230. },
                    Point { x: 20., y: 230. },
                ],
            )
            .unwrap(),
        );
        let line = [
            Point { x: 10., y: 20. },
            Point { x: 10., y: 20. },
            Point { x: 10., y: 40. },
            Point { x: 10., y: 40. },
        ];
        let bounds = geometry
            .project_semantic_quad("root", line)
            .unwrap()
            .bounds();
        assert_eq!(
            bounds,
            Bounds {
                x: 40.,
                y: 70.,
                width: 0.,
                height: 40.
            }
        );
        assert_eq!(
            geometry.project_semantic_quad(
                "root",
                [
                    Point { x: 0., y: 0. },
                    Point { x: 1., y: 0. },
                    Point { x: 2., y: 0. },
                    Point { x: 3., y: 0. }
                ]
            ),
            Err(GeometryError::InvalidGeometry)
        );
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn native_geometry_ignores_legacy_additive_offsets_and_revalidates_viewport() {
        let (client, server, moved, _) = mock_geometry(false).await;
        let (operation, _sender) = mock_operation();
        let frame = mock_frame();
        let geometry =
            GeometrySnapshot::capture(&client, "page", std::slice::from_ref(&frame), &operation)
                .await
                .unwrap();
        let polygons = geometry
            .node_border_polygons(&client, &frame, 7, &operation)
            .await
            .unwrap();
        assert_eq!(
            polygons[0].bounds(),
            Some(Bounds {
                x: 10.,
                y: 20.,
                width: 20.,
                height: 20.
            })
        );
        geometry.revalidate(&client, &operation).await.unwrap();
        moved.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            geometry.revalidate(&client, &operation).await,
            Err(GeometryError::StaleIdentity)
        );
        let refreshed = geometry
            .refresh_after_scroll(&client, &operation)
            .await
            .unwrap();
        refreshed.revalidate(&client, &operation).await.unwrap();
        assert_ne!(refreshed.viewport, geometry.viewport);
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn failed_document_postproof_releases_all_owned_remote_handles() {
        let (client, server, _, log) = mock_geometry(true).await;
        let (operation, _sender) = mock_operation();
        let frame = mock_frame();
        let geometry =
            GeometrySnapshot::capture(&client, "page", std::slice::from_ref(&frame), &operation)
                .await
                .unwrap();
        assert_eq!(
            geometry
                .node_border_polygons(&client, &frame, 7, &operation)
                .await,
            Err(GeometryError::StaleIdentity)
        );
        let mut released = log
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "Runtime.releaseObject")
            .map(|request| request["params"]["objectId"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        released.sort();
        assert_eq!(released, ["exception-owned", "owned-node", "result-owned"]);
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn unexpected_native_frame_or_renderer_is_not_silently_omitted() {
        let (client, server, _, _) = mock_geometry(false).await;
        let (operation, _sender) = mock_operation();
        let mut frame = mock_frame();
        frame.binding.frame = "invented".into();
        assert!(matches!(
            GeometrySnapshot::capture(&client, "page", &[frame], &operation).await,
            Err(GeometryError::IncompleteInventory)
        ));
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    #[ignore = "requires real Chromium; shared frame geometry gate"]
    async fn chromium_shared_nested_frame_geometry_border_padding_scroll_and_scale() {
        use super::super::actions::{execute_command, DaemonState};
        let mut state = DaemonState::new();
        let launch = execute_command(
            &json!({"id":"geometry-launch","action":"launch","headless":true}),
            &mut state,
        )
        .await;
        assert_eq!(launch["success"], true, "{launch}");
        let (sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 987,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let result=async{
            let mgr=state.browser.as_ref().ok_or("Missing browser")?;let session=mgr.active_session_id()?;
            let setup=mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":r#"new Promise(resolve=>{document.body.style.cssText='margin:0;height:3000px';const outer=document.createElement('iframe');outer.id='outer';outer.style.cssText='position:absolute;left:100.25px;top:150.5px;width:200px;height:150px;border:10px solid black;padding:5px;transform:scale(2);transform-origin:0 0';outer.onload=()=>{const d=outer.contentDocument;d.body.style.cssText='margin:0;height:2000px';const inner=d.createElement('iframe');inner.id='inner';inner.style.cssText='position:absolute;left:20px;top:30px;width:80px;height:60px;border:4px solid black;transform:scale(.5);transform-origin:0 0';inner.onload=()=>resolve(true);inner.srcdoc='<body style="margin:0;height:1000px"><input id="secret" type="password" value="synthetic-only" style="position:absolute;left:8px;top:12px;width:16px;height:10px;border:0;padding:0;background:rgb(200,20,40)">';d.body.appendChild(inner);};outer.srcdoc='<body></body>';document.body.appendChild(outer);})"#,"awaitPromise":true,"returnByValue":true})),Some(session)).await?;
            if setup.get("exceptionDetails").is_some(){return Err("Synthetic geometry setup failed".into());}
            for (scrolled,expected_y) in [(false,256.5),(true,154.5)]{
                if scrolled{let scroll=mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"window.scrollTo(0,80);const o=document.querySelector('#outer');o.contentWindow.scrollTo(0,10);o.contentDocument.querySelector('#inner').contentWindow.scrollTo(0,2);true","returnByValue":true})),Some(session)).await?;if scroll.get("exceptionDetails").is_some(){return Err("Synthetic scroll failed".into());}}
                let frames=super::super::client_observation::enumerate_frames(&mgr.client,session,&HashMap::new(),&operation).await.map_err(|_|"Frame enumeration failed")?;
                if frames.len()!=3{return Err("Nested fixture did not produce three frames".into());}
                let snapshot=GeometrySnapshot::capture(&mgr.client,session,&frames,&operation).await.map_err(|e|format!("Geometry proof failed: {e:?}"))?;
                let object=mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('#outer').contentDocument.querySelector('#inner').contentDocument.querySelector('#secret')","returnByValue":false,"objectGroup":"geometry-fixture"})),Some(session)).await?;
                let object=object["result"]["objectId"].as_str().ok_or("Missing synthetic target")?;
                let described=mgr.client.send_command("DOM.describeNode",Some(json!({"objectId":object})),Some(session)).await?;
                let backend=described["node"]["backendNodeId"].as_i64().ok_or("Missing backend")?;
                let frame=frames.iter().find(|f|f.frame_path.len()==2).ok_or("Missing inner frame")?;
                let polygons=snapshot.node_border_polygons(&mgr.client,frame,backend,&operation).await.map_err(|e|format!("Geometry node failed: {e:?}"))?;
                assert_eq!(polygons.len(),1);
                assert_eq!(polygons[0].bounds(),Some(Bounds{x:182.25,y:expected_y,width:16.,height:10.}));
                let clipped=snapshot.clip_for_capture(&frame.binding.frame,&polygons[0]).map_err(|_|"Clip failed")?;
                let expected=PixelBounds{left:182,top:expected_y.floor() as u32,right:199,bottom:(expected_y+10.).ceil() as u32};
                assert_eq!(clipped.raster_bounds(snapshot.viewport,snapshot.viewport.width as u32,snapshot.viewport.height as u32).unwrap(),Some(expected));
                snapshot.revalidate(&mgr.client,&operation).await.map_err(|_|"Stable geometry rejected")?;
                mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('#outer').style.left='101.25px';true","returnByValue":true})),Some(session)).await?;
                assert_eq!(snapshot.revalidate(&mgr.client,&operation).await,Err(GeometryError::StaleIdentity));
                mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('#outer').style.left='100.25px';true","returnByValue":true})),Some(session)).await?;
                mgr.client.send_command("Runtime.releaseObjectGroup",Some(json!({"objectGroup":"geometry-fixture"})),Some(session)).await?;
            }
            let fragmented=mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"const c=document.createElement('div');c.style.cssText='position:absolute;left:25px;top:450px;width:60px;font:16px/20px monospace';c.innerHTML='<span id=fragmented>one two three four five six seven</span>';document.body.appendChild(c);document.querySelector('#fragmented')","returnByValue":false,"objectGroup":"geometry-inline"})),Some(session)).await?;
            let object=fragmented["result"]["objectId"].as_str().ok_or("Missing inline fixture")?;
            let expected=mgr.client.send_command("Runtime.callFunctionOn",Some(json!({"objectId":object,"functionDeclaration":"function(){const r=this.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height};}","returnByValue":true})),Some(session)).await?;
            let expected=&expected["result"]["value"];
            let described=mgr.client.send_command("DOM.describeNode",Some(json!({"objectId":object})),Some(session)).await?;
            let backend=described["node"]["backendNodeId"].as_i64().ok_or("Missing inline backend")?;
            let frames=super::super::client_observation::enumerate_frames(&mgr.client,session,&HashMap::new(),&operation).await.map_err(|_|"Inline inventory failed")?;
            let geometry=GeometrySnapshot::capture(&mgr.client,session,&frames,&operation).await.map_err(|_|"Inline geometry failed")?;
            let main=frames.iter().find(|f|f.parent_frame_id.is_none()).ok_or("Missing main frame")?;
            let polygons=geometry.node_border_polygons(&mgr.client,main,backend,&operation).await.map_err(|_|"Inline border proof failed")?;
            let b=polygons[0].bounds().ok_or("Inline bounds missing")?;
            // CDP JSON may encode integral coordinates as integers, while native
            // bounds serialize f64. Compare exact numeric coordinates, not JSON
            // Number representation (25 and 25.0 are distinct serde Values).
            let expected=Bounds{x:expected["x"].as_f64().ok_or("Missing expected x")?,y:expected["y"].as_f64().ok_or("Missing expected y")?,width:expected["width"].as_f64().ok_or("Missing expected width")?,height:expected["height"].as_f64().ok_or("Missing expected height")?};
            if b!=expected{return Err(format!("Native inline union differs from public bounding rectangle: native={b:?}, expected={expected:?}"));}
            mgr.client.send_command("Runtime.releaseObjectGroup",Some(json!({"objectGroup":"geometry-inline"})),Some(session)).await?;
            Ok::<(),String>(())
        }.await;
        drop(sender);
        let close =
            execute_command(&json!({"id":"geometry-close","action":"close"}), &mut state).await;
        assert_eq!(close["success"], true, "{close}");
        result.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires real Chromium and synthetic loopback HTTP; nested OOPIF geometry gate"]
    async fn chromium_shared_nested_oopif_geometry_uses_proven_renderer_roots() {
        use super::super::actions::{execute_command, DaemonState};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let main_url = format!("http://127.0.0.1:{port}/main");
        let child_url = format!("http://localhost:{port}/child");
        let leaf_url = format!("http://127.0.0.1:{port}/leaf");
        let child_for_server = child_url.clone();
        let leaf_for_server = leaf_url.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{let Ok((mut socket,_))=accepted else{break};let child=child_for_server.clone();let leaf=leaf_for_server.clone();connections.spawn(async move{let mut request=[0u8;8192];let Ok(n)=socket.read(&mut request).await else{return};let path=std::str::from_utf8(&request[..n]).unwrap_or("").split_whitespace().nth(1).unwrap_or("");let html=match path{
                        "/main"=>format!("<body style='margin:0'><iframe onload='window.ready=true' src='{child}' style='position:absolute;left:100px;top:150px;width:200.5px;height:150px;border:8px solid black;padding:4px;transform:scale(1.5);transform-origin:0 0'></iframe>"),
                        "/child"=>format!("<body style='margin:0'><iframe src='{leaf}' style='position:absolute;left:10px;top:20px;width:100.25px;height:80px;border:2px solid black;transform:scale(2);transform-origin:0 0'></iframe>"),
                        "/leaf"=>"<body style='margin:0;height:1000px'><input id='secret' type='password' value='synthetic-only' style='position:absolute;left:3px;top:5px;width:10px;height:8px;border:0;padding:0;background:rgb(200,20,40);color:transparent'>".to_string(),_=>String::new()};let response=format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",html.len());let _=socket.write_all(response.as_bytes()).await;});},
                    _=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
        });
        let mut state = DaemonState::new();
        let launch=execute_command(&json!({"id":"oopif-launch","action":"launch","headless":true,"args":["--site-per-process"]}),&mut state).await;
        assert_eq!(launch["success"], true, "{launch}");
        let (_sender, cancellation) = tokio::sync::watch::channel(CancelSignal::None);
        let operation = OperationLease {
            is_callback: false,
            generation: 1,
            sequence: 988,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation,
        };
        let result=async{
            let mgr=state.browser.as_ref().ok_or("Missing browser")?;let session=mgr.active_session_id()?;
            mgr.client.send_command("Emulation.setDeviceMetricsOverride",Some(json!({"width":800,"height":600,"deviceScaleFactor":2,"mobile":false})),Some(session)).await?;
            mgr.client.send_command("Page.navigate",Some(json!({"url":main_url})),Some(session)).await?;
            loop {let ready=mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"window.ready===true","returnByValue":true})),Some(session)).await?;if ready["result"]["value"]==true{break;}check(&operation).map_err(|_|"Fixture load deadline")?;tokio::time::sleep(Duration::from_millis(20)).await;}
            let targets=mgr.client.send_command("Target.getTargets",None,None).await?;
            let targets=targets["targetInfos"].as_array().ok_or("Missing targets")?;
            let mut registry=HashMap::new();let mut owned_sessions=Vec::new();let mut leaf_session=None;
            for target in targets.iter().filter(|t|t["type"]=="iframe"&&(t["url"]==child_url||t["url"]==leaf_url)){
                let attached=mgr.client.send_command("Target.attachToTarget",Some(json!({"targetId":target["targetId"],"flatten":true})),None).await?;
                let attached=attached["sessionId"].as_str().ok_or("Missing owned fixture session")?.to_owned();
                let tree=mgr.client.send_command("Page.getFrameTree",None,Some(&attached)).await?;
                let frame=tree["frameTree"]["frame"]["id"].as_str().ok_or("Missing native renderer root")?.to_owned();
                if target["url"]==leaf_url{leaf_session=Some(attached.clone());}
                registry.insert(frame,attached.clone());owned_sessions.push(attached);
            }
            if registry.len()!=2{return Err("Site isolation did not produce two independently verified OOPIF roots".into());}
            let frames=super::super::client_observation::enumerate_frames(&mgr.client,session,&registry,&operation).await.map_err(|e|format!("OOPIF enumeration failed: {e:?}"))?;
            if frames.len()!=3{return Err("OOPIF frame inventory incomplete".into());}
            let geometry=GeometrySnapshot::capture(&mgr.client,session,&frames,&operation).await.map_err(|e|format!("OOPIF geometry capture: {e:?}"))?;
            let leaf_session=leaf_session.ok_or("Missing leaf session")?;
            let target=mgr.client.send_command("Runtime.evaluate",Some(json!({"expression":"document.querySelector('#secret')","returnByValue":false,"objectGroup":"oopif-fixture"})),Some(&leaf_session)).await?;
            let described=mgr.client.send_command("DOM.describeNode",Some(json!({"objectId":target["result"]["objectId"]})),Some(&leaf_session)).await?;
            let backend=described["node"]["backendNodeId"].as_i64().ok_or("Missing leaf backend")?;
            let frame=frames.iter().find(|f|f.binding.session==leaf_session).ok_or("Missing leaf frame proof")?;
            let polygons=geometry.node_border_polygons(&mgr.client,frame,backend,&operation).await.map_err(|e|format!("OOPIF node geometry: {e:?}"))?;
            assert_eq!(polygons[0].bounds(),Some(Bounds{x:148.,y:219.,width:30.,height:24.}));
            // Actual PNG size supplies raster scale, independently of DPR flags.
            let png=mgr.client.send_command("Page.captureScreenshot",Some(json!({"format":"png","fromSurface":true,"captureBeyondViewport":false})),Some(session)).await?;
            use base64::Engine;let bytes=base64::engine::general_purpose::STANDARD.decode(png["data"].as_str().ok_or("Missing PNG")?).map_err(|_|"Invalid PNG")?;
            let image=image::load_from_memory(&bytes).map_err(|_|"PNG decode failed")?.to_rgb8();
            let clipped=geometry.clip_for_capture(&frame.binding.frame,&polygons[0]).map_err(|_|"OOPIF clipping failed")?;
            let mask=clipped.raster_bounds(geometry.viewport,image.width(),image.height()).map_err(|_|"Raster proof failed")?.ok_or("Missing mask")?;
            let center=image.get_pixel((mask.left+mask.right)/2,(mask.top+mask.bottom)/2).0;
            // The geometric center is below the native password text baseline in
            // this tiny input; exact solid synthetic background establishes that
            // projected coordinates refer to the actual leaf, not its parent.
            assert_eq!(center,[200,20,40]);
            geometry.revalidate(&mgr.client,&operation).await.map_err(|_|"Stable OOPIF geometry rejected")?;
            mgr.client.send_command("Runtime.releaseObjectGroup",Some(json!({"objectGroup":"oopif-fixture"})),Some(&leaf_session)).await?;
            for session in owned_sessions{mgr.client.send_command("Target.detachFromTarget",Some(json!({"sessionId":session})),None).await?;}
            Ok::<(),String>(())
        }.await;
        let close =
            execute_command(&json!({"id":"oopif-close","action":"close"}), &mut state).await;
        server.abort();
        let _ = server.await;
        assert_eq!(close["success"], true, "{close}");
        result.unwrap();
    }
}

#[cfg(test)]
#[path = "client_readonly_disposal_tests.rs"]
mod readonly_disposal_tests;
