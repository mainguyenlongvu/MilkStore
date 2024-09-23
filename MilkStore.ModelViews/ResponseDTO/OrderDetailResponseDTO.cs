using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class OrderDetailResponseDTO
    {
        public string ProductID { get; set; }
        public required int Quantity { get; set; }
        public double UnitPrice { get; set; }
        public double TotalAmount => Quantity * UnitPrice;
    }
}
