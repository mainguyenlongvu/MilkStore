using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class GiftResponseDTO
    {
        public string Id {  get; set; }
        public int point { get; set; }
        public string GiftName { get; set; }
        public string? ProductId { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.Now;
        public required string CreatedBy { get; set; }
        public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.Now;
        public DateTimeOffset? DeletedTime { get; set; } = null;
    }
}
