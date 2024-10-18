using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.CustomerModelViews
{
    public enum CustomerOrderAction
    {
        ChangeShippingAddress,
        RequestReturn,
        CancelOrder
    }
    public class CustomerOrderUpdateModel
    {
        public CustomerOrderAction Action { get; set; }
        public string? NewShippingAddress { get; set; }
    }
}
