using MilkStore.ModelViews.PreOrdersModelView;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class PreOdersResponseDTO
    {
        public string Id { get; set; }
        public required Guid UserID { get; set; }
        public string ProductID { get; set; }
        public required PreOrderStatus Status { get; set; }
    }
}
