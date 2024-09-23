using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.OrderDetailsModelView
{
    public class OrderDetailsModelView
    {
        public string OrderID { get; set; }
        public string ProductID { get; set; }
        public required int Quantity { get; set; }
        [JsonIgnore]
        public double UnitPrice { get; set; }
        public double TotalAmount => Quantity * UnitPrice;
    }
}
