using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    
    public class OrderDetailResponseDTO
    {
        public string Id { get; set; }
        public string? OrderID { get; set; }
        public string? ProductID { get; set; }
        public required int Quantity { get; set; }
        public double UnitPrice { get; set; }
        public double TotalAmount => Quantity * UnitPrice;
        public string Status { get; set; }


    }
}
