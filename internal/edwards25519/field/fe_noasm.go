package field

func feMul(v, x, y *Element)                { feMulGeneric(v, x, y) }
func feSquare(v, x *Element)                { feSquareGeneric(v, x) }
func (v *Element) carryPropagate() *Element { return v.carryPropagateGeneric() }
